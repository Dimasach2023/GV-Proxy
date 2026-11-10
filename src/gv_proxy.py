#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gv_proxy.py - replaces dead googlevideo nodes (rrN---sn-pivhx-*.googlevideo.com) with a working node
taken from the mn= parameter of the link itself. Traffic is intercepted with WinDivert.

Configuration: blocked.txt next to the script - the dead nodes. Where to redirect, the proxy decides itself -
from the mn= parameter in the link.

How it works:
  1) WinDivert turns connections to the addresses of the dead nodes into connections to the local proxy;
  2) the proxy terminates TLS with its own *.googlevideo.com certificate (the only way to read mn=);
  3) picks a working node from mn= (or --fallback-host), connects to it (its SNI + Host), rewrites Host;
  4) pipes bytes back and forth.

Commands (anything that changes the system needs administrator rights; the .bat requests them itself):
  gen                 - create certificates (the CA key is discarded immediately)
  run                 - run in this window
  setup               - certificate + firewall rule
  install             - setup + background run without a window + autostart at Windows logon
  uninstall-autostart - stop and remove autostart
  uninstall           - remove everything the script installed
  stop                - stop the running process
  check               - diagnostics: WinDivert, DNS of the dead nodes, filter
"""
import argparse
import asyncio
import base64
import ctypes
import datetime
import hashlib
import ipaddress
import itertools
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

HERE = Path(__file__).resolve().parent     # <root>/src
ROOT = HERE.parent                         # <root>: setup .bat, blocked.txt
BIN = ROOT / "bin"                         # WinDivert.dll, WinDivert64.sys
DATA = ROOT / "data"                       # generated: certificates, log
CA_CER = DATA / "gv_ca.cer"        # DER, installed into the trusted roots
LEAF_CRT = DATA / "gv_leaf.crt"    # certificate for *.googlevideo.com
LEAF_KEY = DATA / "gv_leaf.key"    # its key
HOST_RE = re.compile(r"^rr(\d+)---(sn-[a-z0-9-]+)\.googlevideo\.com$", re.I)
BLOCKED_FILE = ROOT / "blocked.txt"
DEFAULT_BLOCKED = """# Dead googlevideo nodes that should be redirected.
# One per line (# starts a comment). Accepted forms:
#   rr3---sn-pivhx-n8vs.googlevideo.com   - one exact address
#   rr*---sn-pivhx-n8vs.googlevideo.com   - the same node on every rr1..rr30
#   sn-pivhx-n8vs                         - short form of the line above
# The addresses of these names are looked up in DNS and diverted by WinDivert.
# The list is re-read every 5 minutes; to apply a change at once run the Install item again.
""" + "".join(
    f"rr{_r}---sn-pivhx-{_s}.googlevideo.com\n"
    for _r in range(1, 31) for _s in ("n8vs", "n8vz", "n8v6", "n8vd")
)

RR_MAX = 30   # rr* in blocked.txt expands to rr1 .. rr30
LOG_FILE = DATA / "gv_proxy.log"
TASK_NAME = "GV Proxy"
FW_RULE = "GV Proxy local port"
DEFAULT_PORT = 18443      # local port of the proxy (WinDivert redirects to it, so it is not 443 any more)
CA_NAME = "GV Local CA (googlevideo.com only)"
LOG_TO_FILE = False

# --- stability tuning
UP_CONNECT_TIMEOUT = 6      # total seconds to get a connection + TLS handshake to one node
HEDGE_DELAY = 1.0           # a lost SYN costs 3 s on Windows: start another attempt after this many seconds
UP_ATTEMPTS = 4             # at most this many staggered attempts per node (spread over its rr names / IPs)
ALT_RR_POOL = (1, 2, 3, 4, 5, 6, 7, 8)  # other rrN names of the same node = other IP addresses of it
ALT_PER_NODE = 3            # how many of them are tried besides the rr of the original host
UP_MAX_IPS = 2              # how many IPs of one node to try before moving to the next node
DNS_TTL = 300               # seconds a resolved node name is cached
BAD_TTL = 120               # seconds a failed (node, ip) is deprioritised
IDLE_TIMEOUT = 120          # seconds of silence after which an idle connection is dropped
DEFAULT_LISTEN = ["0.0.0.0", "::"]   # redirected packets arrive on our own address, not on loopback
RESP_HEAD_TIMEOUT = 15      # seconds to wait for the response head of a node
MAX_BUFFERED_BODY = 262144  # request bodies up to this size are buffered so the request can be replayed
RETRY_STATUS = {400, 403}   # (and every 5xx): the node's answer after which another node is tried


# ----------------------------------------------------------------- certificates
def gen_certs():
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "GV Local CA (googlevideo.com only)")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=370))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        # the CA may only sign googlevideo.com and its subdomains
        .add_extension(x509.NameConstraints([x509.DNSName("googlevideo.com")], None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "*.googlevideo.com")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("*.googlevideo.com")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    DATA.mkdir(parents=True, exist_ok=True)
    CA_CER.write_bytes(ca.public_bytes(serialization.Encoding.DER))
    LEAF_CRT.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    LEAF_KEY.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    # the CA key is never saved: it disappears when the function returns
    print("Certificates created:", CA_CER.name, LEAF_CRT.name, LEAF_KEY.name)
    print("The CA key is not saved (by design): new certificates cannot be issued, only everything recreated.")


# ----------------------------------------------------------------- HTTP utilities
def parse_head(head: bytes):
    first, _, rest = head.partition(b"\r\n")
    parts = first.split(b" ")
    method = parts[0].decode("latin1") if parts else ""
    target = parts[1].decode("latin1") if len(parts) > 1 else "/"
    headers = {}
    for line in rest.split(b"\r\n"):
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().lower().decode("latin1")] = v.strip().decode("latin1")
    return method, target, headers


def parse_status(head: bytes) -> int:
    try:
        return int(head.split(b" ", 2)[1])
    except Exception:
        return 0


async def copy_exact(src, dst, n, timeout):
    """Copies exactly n bytes src -> dst."""
    while n > 0:
        chunk = await asyncio.wait_for(src.read(min(65536, n)), timeout)
        if not chunk:
            raise ConnectionError("unexpected end of stream")
        dst.write(chunk)
        n -= len(chunk)
        await dst.drain()


async def relay_chunked(src, dst, timeout):
    """Copies a chunked body (to the final 0-chunk and trailers) so we know where the message ends."""
    while True:
        line = await asyncio.wait_for(src.readline(), timeout)
        if not line:
            raise ConnectionError("unexpected end of chunked body")
        dst.write(line)
        try:
            size = int(line.split(b";", 1)[0].strip() or b"0", 16)
        except ValueError:
            raise ConnectionError("bad chunk size")
        if size == 0:
            while True:  # trailers up to the empty line
                t = await asyncio.wait_for(src.readline(), timeout)
                dst.write(t)
                if t in (b"\r\n", b"\n", b""):
                    break
            await dst.drain()
            return
        await copy_exact(src, dst, size + 2, timeout)  # data + CRLF


def rewrite_host(head: bytes, new_host: str) -> bytes:
    return re.sub(rb"(?im)^host:[^\r\n]*", b"Host: " + new_host.encode("ascii"), head, count=1)


def log(msg: str):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    if sys.stdout is not None:  # there is no console under pythonw
        try:
            print(line, flush=True)
        except Exception:
            pass
    if LOG_TO_FILE:
        try:
            DATA.mkdir(parents=True, exist_ok=True)
            if LOG_FILE.exists() and LOG_FILE.stat().st_size > 1_000_000:
                os.replace(LOG_FILE, LOG_FILE.with_suffix(".log.old"))
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass


# ----------------------------------------------------------------- blocked.txt
def ensure_config_files():
    """Creates the default blocked.txt only if it does not exist yet (an existing one is left alone)."""
    if not BLOCKED_FILE.exists():
        try:
            with open(BLOCKED_FILE, "w", encoding="utf-8", newline="") as f:
                f.write(DEFAULT_BLOCKED.replace("\n", "\r\n"))
        except OSError as e:
            log(f"Could not create {BLOCKED_FILE.name}: {e}")


def _read_tokens(path: Path):
    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return []
    except OSError as e:
        log(f"Could not read {path.name}: {e}")
        return []
    out = []
    for line in text.splitlines():
        out += [t for t in re.split(r"[\s,;]+", line.split("#", 1)[0]) if t]
    return out


def parse_node(token: str, source: str):
    """-> (rr, node); rr is None for "every rr" (rr*--- or a bare node name). None if the entry is invalid."""
    t = token.lower().rstrip(".")
    if t.endswith(".googlevideo.com"):
        t = t[: -len(".googlevideo.com")]
    m = re.fullmatch(r"rr(\d+|\*)---(sn-[a-z0-9-]+)", t)
    if m:
        return (None if m.group(1) == "*" else int(m.group(1))), m.group(2)
    m = re.fullmatch(r"(sn-[a-z0-9-]+)", t)
    if m:
        return None, m.group(1)
    log(f"{source}: skipping '{token}' (expected rrN---sn-xxxx.googlevideo.com, rr*---sn-xxxx.googlevideo.com or sn-xxxx)")
    return None


def load_blocked_hosts():
    """List of host names from blocked.txt (rr* / bare node names are expanded)."""
    hosts = set()
    for tok in _read_tokens(BLOCKED_FILE):
        n = parse_node(tok, BLOCKED_FILE.name)
        if n:
            for rr in ([n[0]] if n[0] is not None else range(1, RR_MAX + 1)):
                hosts.add(f"rr{rr}---{n[1]}.googlevideo.com")
    return sorted(hosts)


def load_dead():
    """(nodes, hosts, families) from blocked.txt for the mn= mode.
      nodes    - dead on EVERY rr: written as rr*---node or as a bare node name;
      hosts    - dead only under that exact name: written as rrN---node (other rr names of the node still work);
      families - the node prefix without the last block: sn-pivhx-n8vs -> sn-pivhx. This is how the original
                 script worked (it skipped all sn-pivhx*)."""
    nodes, hosts, all_nodes = set(), set(), set()
    for tok in _read_tokens(BLOCKED_FILE):
        n = parse_node(tok, BLOCKED_FILE.name)
        if not n:
            continue
        all_nodes.add(n[1])
        if n[0] is None:
            nodes.add(n[1])
        else:
            hosts.add(f"rr{n[0]}---{n[1]}.googlevideo.com")
    families = {x.rsplit("-", 1)[0] for x in all_nodes if x.count("-") >= 2}
    return nodes, hosts, families


# ----------------------------------------------------------------- system operations (Windows)
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def need_admin():
    if is_admin():
        return
    print("Administrator rights are required. Run via gv_proxy_setup.bat - it requests them itself.")
    sys.exit(1)


def _dec(b: bytes) -> str:
    for enc in ("utf-8", "oem"):
        try:
            return b.decode(enc)
        except Exception:
            pass
    return b.decode("utf-8", "replace")


def _psq(s) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def run_quiet(cmd):
    """Runs a child process in its own hidden console: it cannot change the title,
    font or size of the window the script was started from (powershell.exe used to do that)."""
    return subprocess.run(
        cmd, capture_output=True, stdin=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def powershell(script: str):
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    r = run_quiet(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc]
    )
    return r.returncode, _dec(r.stdout).strip(), _dec(r.stderr).strip()


# --- certificate
def ensure_certs():
    if not (CA_CER.exists() and LEAF_CRT.exists() and LEAF_KEY.exists()):
        gen_certs()


def cert_add():
    r = run_quiet(["certutil", "-addstore", "-f", "Root", str(CA_CER)])
    if r.returncode != 0:
        print("Could not add the certificate:", _dec(r.stdout + r.stderr).strip())
        sys.exit(1)
    print("Certificate added to the trusted roots.")


def cert_remove():
    if CA_CER.exists():  # exact removal by the thumbprint of our certificate
        thumb = hashlib.sha1(CA_CER.read_bytes()).hexdigest()
        run_quiet(["certutil", "-delstore", "Root", thumb])
    for _ in range(10):  # old copies with the same unique name (after regeneration)
        if run_quiet(["certutil", "-delstore", "Root", CA_NAME]).returncode != 0:
            break
    print("Certificate removed.")


def fw_add(port):
    fw_remove(quiet=True)
    r = run_quiet(["netsh", "advfirewall", "firewall", "add", "rule", f"name={FW_RULE}", "dir=in",
                   "action=allow", "protocol=TCP", f"localport={port}", "profile=any"])
    print("Firewall rule added (incoming TCP port %d)." % port if r.returncode == 0
          else "Could not add the firewall rule: " + _dec(r.stdout + r.stderr).strip())


def fw_remove(quiet=False):
    run_quiet(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_RULE}"])
    if not quiet:
        print("Firewall rule removed.")


def remove_cert_files():
    for f in (CA_CER, LEAF_CRT, LEAF_KEY):
        try:
            f.unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            print("Could not delete", f.name, e)


def need_windivert():
    missing = [f.name for f in (WD_DLL, WD_SYS) if not f.exists()]
    if missing:
        print("Missing in the bin folder:", ", ".join(missing), "(WinDivert 2.2.2, x64). Run gv_proxy_setup.bat again.")
        sys.exit(1)


# --- background run and autostart
def stop_proxy():
    script = str(HERE / "gv_proxy.py")
    ps = f"""
$ErrorActionPreference = 'SilentlyContinue'
Stop-ScheduledTask -TaskName {_psq(TASK_NAME)}
$p = {_psq(script)}
Get-CimInstance Win32_Process | Where-Object {{
    $_.ProcessId -ne {os.getpid()} -and $_.CommandLine -and
    $_.CommandLine.IndexOf($p, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
    $_.CommandLine -match 'gv_proxy\\.py"?\\s+run\\b'
}} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}
"""
    powershell(ps)
    run_quiet(["taskkill", "/fi", "WINDOWTITLE eq GVP-run", "/f"])
    print("Proxy stopped (if it was running).")


def autostart_on(port):
    pyw = Path(sys.executable).with_name("pythonw.exe")
    if not pyw.exists():
        print("pythonw.exe not found next to", sys.executable, "- it is required to run without a window.")
        sys.exit(1)
    script = str(HERE / "gv_proxy.py")
    ps = f"""
$ErrorActionPreference = 'Stop'
$me  = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$act = New-ScheduledTaskAction -Execute {_psq(pyw)} -Argument {_psq('"' + script + f'" run --port {port} --log')} -WorkingDirectory {_psq(HERE)}
$trg = New-ScheduledTaskTrigger -AtLogOn -User $me
$pri = New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive -RunLevel Highest
$set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
       -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) `
       -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName {_psq(TASK_NAME)} -Action $act -Trigger $trg -Principal $pri -Settings $set `
       -Description 'Local googlevideo proxy (gv_proxy.py)' -Force | Out-Null
"""
    code, out, err = powershell(ps)
    if code != 0:
        print("Could not create the autostart task:", err or out)
        sys.exit(1)
    print(f"Autostart enabled (Task Scheduler task '{TASK_NAME}', at Windows logon, no window).")


def autostart_off():
    powershell(f"Unregister-ScheduledTask -TaskName {_psq(TASK_NAME)} -Confirm:$false -ErrorAction SilentlyContinue")
    print("Autostart removed.")


def start_background():
    try:
        pos = LOG_FILE.stat().st_size
    except OSError:
        pos = 0
    code, out, err = powershell(f"Start-ScheduledTask -TaskName {_psq(TASK_NAME)}")
    if code != 0:
        print("Could not start the task:", err or out)
        sys.exit(1)
    for _ in range(40):
        time.sleep(0.5)
        try:
            with open(LOG_FILE, "rb") as f:
                f.seek(pos)
                new = f.read().decode("utf-8", "replace")
        except OSError:
            continue
        if "[divert] active" in new:
            print("WinDivert is active, the proxy is running in the background.")
            return
        if "[divert] ERROR" in new:
            print("Failed to start:", [l for l in new.splitlines() if "ERROR" in l][-1])
            return
    print(f"No confirmation within 20 s (DNS may be slow). See the log: {LOG_FILE}")


# --- scenarios
def cmd_setup(port):
    need_admin()
    need_windivert()
    ensure_config_files()
    ensure_certs()
    cert_add()
    fw_add(port)


def cmd_install(port):
    need_admin()
    stop_proxy()
    cmd_setup(port)
    autostart_on(port)
    start_background()
    print("Done. Fully restart Chrome/Edge (Firefox does not use the system certificates).")


def cmd_uninstall_autostart():
    need_admin()
    stop_proxy()
    autostart_off()


def cmd_uninstall():
    need_admin()
    stop_proxy()
    autostart_off()
    cert_remove()
    fw_remove()
    remove_cert_files()
    for f in (LOG_FILE, LOG_FILE.with_suffix(".log.old")):
        try:
            f.unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            print("Could not delete", f.name, e)
    try:
        DATA.rmdir()
    except OSError:
        pass
    print("Done: autostart, certificate, keys and firewall rule removed (WinDivert files stay in bin).")


def cmd_check(args):
    print("Python:", sys.version.split()[0], "| administrator:", is_admin() if os.name == "nt" else "n/a (not Windows)")
    print("WinDivert.dll:", WD_DLL.exists(), "| WinDivert64.sys:", WD_SYS.exists())
    names = load_blocked_hosts()
    print(f"blocked.txt: {len(names)} names; resolving...")
    found = resolve_dead_ips(names)
    for b in sorted(found):
        print("  ", unpack_ip(b), "<-", ", ".join(sorted(n.split(".")[0] for n in found[b]))[:90])
    print("dead addresses:", len(found))
    flt = build_filter(args.port, frozenset(found), not args.keep_quic)
    print("filter:", flt)
    if os.name == "nt" and WD_DLL.exists():
        try:
            wd = WinDivert()
            print("filter compiles:", wd.check_filter(flt) or "yes" if flt else "n/a")
            wd.close(wd.open("false", 0))
            print("WinDivert driver: loads and opens OK")
        except OSError as e:
            print("WinDivert ERROR:", e)
    print("certificate files:", all(f.exists() for f in (CA_CER, LEAF_CRT, LEAF_KEY)))


# ----------------------------------------------------------------- WinDivert: packet layer
# The packets themselves are redirected. Addresses of the dead nodes are
# resolved by the normal DNS (names from blocked.txt). For every connection to such an address the
# outgoing packet "A:cp -> S:443" is turned into the incoming "S:cp -> A:PORT" (A = our own address,
# S = the dead node). The local proxy accepts it, and the peer address of the accepted socket IS the
# original destination. Replies of the proxy "A:PORT -> S:cp" are turned back into "S:443 -> A:cp".
# Nothing is stored per connection. UDP/443 (QUIC) to the dead addresses is dropped so that the
# browser falls back to TCP.
WD_DLL = BIN / "WinDivert.dll"
WD_SYS = BIN / "WinDivert64.sys"
WD_PRIORITY = 1000          # above zapret/winws (0): our rewrite happens first
FILTER_TERMS_MAX = 200      # WinDivert allows 256 filter objects in total
DEAD_REFRESH = 300          # seconds between DNS refreshes of the dead names
DEAD_KEEP = 3600            # an address that stopped resolving is still diverted for this long
SYN, ACK = 0x02, 0x10
SVC_NAME = "WinDivert"      # the driver service; "net stop WinDivert" (zapret service removal) hangs while a handle is open
SVC_POLL = 0.5              # seconds between checks of its state
SVC_REGRAB_DELAY = 10.0     # after the stop request is over, wait this long before taking the driver back
ZAPRET_SVC = "zapret"       # service of zapret/winws (service.bat); its stop means that WinDivert is about to be stopped
SVC_STOPPED, SVC_STOP_PENDING, SVC_RUNNING = 1, 3, 4


def pack_ip(text: str):
    text = text.split("%", 1)[0]
    try:
        return socket.inet_pton(socket.AF_INET6 if ":" in text else socket.AF_INET, text)
    except OSError:
        return None


def unpack_ip(b: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6 if len(b) == 16 else socket.AF_INET, b)


def _sum16(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    return sum(struct.unpack("!%dH" % (len(data) // 2), data))


def _fold(s: int) -> int:
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return s


class Pkt:
    __slots__ = ("v", "ihl", "end", "proto", "src", "dst", "sport", "dport", "flags", "seq", "ack")


def parse_packet(buf):
    """IPv4/IPv6 + TCP/UDP header fields, or None (fragments, extension headers, other protocols)."""
    if len(buf) < 20:
        return None
    p = Pkt()
    p.v = buf[0] >> 4
    if p.v == 4:
        p.ihl = (buf[0] & 15) * 4
        if p.ihl < 20 or len(buf) < p.ihl or struct.unpack_from("!H", buf, 6)[0] & 0x3FFF:
            return None
        total = struct.unpack_from("!H", buf, 2)[0]
        p.end = total if 0 < total <= len(buf) else len(buf)   # 0 with segmentation offload
        p.proto, p.src, p.dst = buf[9], bytes(buf[12:16]), bytes(buf[16:20])
    elif p.v == 6:
        if len(buf) < 40:
            return None
        p.ihl = 40
        plen = struct.unpack_from("!H", buf, 4)[0]
        p.end = 40 + plen if 0 < 40 + plen <= len(buf) else len(buf)
        p.proto, p.src, p.dst = buf[6], bytes(buf[8:24]), bytes(buf[24:40])
    else:
        return None
    p.sport = p.dport = p.flags = p.seq = p.ack = 0
    if p.proto == 6 and p.end >= p.ihl + 20:
        p.sport, p.dport, p.seq, p.ack = struct.unpack_from("!HHII", buf, p.ihl)
        p.flags = buf[p.ihl + 13]
    elif p.proto == 17 and p.end >= p.ihl + 8:
        p.sport, p.dport = struct.unpack_from("!HH", buf, p.ihl)
    else:
        return None
    return p


def fix_checksums(buf: bytearray, p: Pkt):
    """Recomputes the IPv4 header and TCP checksums from scratch."""
    if p.v == 4:
        buf[10:12] = b"\0\0"
        struct.pack_into("!H", buf, 10, ~_fold(_sum16(bytes(buf[:p.ihl]))) & 0xFFFF)
    l4 = p.end - p.ihl
    # the addresses may have been swapped in the buffer, so they are taken from the buffer, not from p
    if p.v == 4:
        pseudo = bytes(buf[12:20]) + struct.pack("!BBH", 0, 6, l4)
    else:
        pseudo = bytes(buf[8:40]) + struct.pack("!IBBBB", l4, 0, 0, 0, 6)
    buf[p.ihl + 16:p.ihl + 18] = b"\0\0"
    c = ~_fold(_sum16(pseudo) + _sum16(bytes(buf[p.ihl:p.end]))) & 0xFFFF
    struct.pack_into("!H", buf, p.ihl + 16, c)


def _swap_addrs(buf: bytearray, p: Pkt):
    if p.v == 4:
        buf[12:16], buf[16:20] = buf[16:20], buf[12:16]
    else:
        buf[8:24], buf[24:40] = buf[24:40], buf[8:24]


def reflect_to_proxy(buf: bytearray, p: Pkt, proxy_port: int):
    """A:cp -> S:443   becomes   S:cp -> A:proxy_port (to be injected as an INCOMING packet)."""
    _swap_addrs(buf, p)
    struct.pack_into("!H", buf, p.ihl + 2, proxy_port)
    fix_checksums(buf, p)


def reflect_from_proxy(buf: bytearray, p: Pkt):
    """A:proxy_port -> S:cp   becomes   S:443 -> A:cp (to be injected as an INCOMING packet)."""
    _swap_addrs(buf, p)
    struct.pack_into("!H", buf, p.ihl, 443)
    fix_checksums(buf, p)


# ----------------------------------------------------------------- WinDivert: driver access (ctypes)
class WdAddress(ctypes.Structure):
    """WINDIVERT_ADDRESS, 80 bytes (see windivert.h of version 2.2)."""
    _fields_ = [("Timestamp", ctypes.c_int64), ("Flags", ctypes.c_uint32),
                ("Reserved2", ctypes.c_uint32), ("Data", ctypes.c_uint8 * 64)]
    F_OUTBOUND, F_IPCS, F_TCPCS, F_UDPCS = 1 << 17, 1 << 21, 1 << 22, 1 << 23

    @property
    def outbound(self) -> bool:
        return bool(self.Flags & self.F_OUTBOUND)

    def make_inbound_valid(self):
        """The packet is injected as an incoming one, with checksums that we computed ourselves."""
        self.Flags = (self.Flags & ~self.F_OUTBOUND) | self.F_IPCS | self.F_TCPCS


WD_ERRORS = {
    2: "WinDivert64.sys was not found next to WinDivert.dll (bin folder)",
    5: "access denied: run as administrator",
    87: "invalid parameter (the filter was rejected)",
    577: "Windows refused to load the driver signature (Secure Boot / Memory integrity / old Windows?)",
    1060: "the WinDivert driver service does not exist (WinDivert64.sys missing?)",
    1275: "the driver is blocked by Windows (driver blocklist / security software)",
    1753: "the Base Filtering Engine service is not running",
}


class WinDivert:
    def __init__(self, dll_path=WD_DLL):
        if os.name != "nt":
            raise OSError("WinDivert works only on Windows")
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            raise OSError("64-bit Python is required (WinDivert64.sys is bundled)")
        c = ctypes
        d = c.WinDLL(str(dll_path), use_last_error=True)
        d.WinDivertOpen.argtypes = [c.c_char_p, c.c_int, c.c_int16, c.c_uint64]
        d.WinDivertOpen.restype = c.c_void_p
        d.WinDivertRecv.argtypes = [c.c_void_p, c.c_void_p, c.c_uint, c.POINTER(c.c_uint), c.POINTER(WdAddress)]
        d.WinDivertRecv.restype = c.c_int
        d.WinDivertSend.argtypes = [c.c_void_p, c.c_char_p, c.c_uint, c.POINTER(c.c_uint), c.POINTER(WdAddress)]
        d.WinDivertSend.restype = c.c_int
        d.WinDivertShutdown.argtypes = [c.c_void_p, c.c_int]
        d.WinDivertShutdown.restype = c.c_int
        d.WinDivertClose.argtypes = [c.c_void_p]
        d.WinDivertClose.restype = c.c_int
        d.WinDivertHelperCompileFilter.argtypes = [c.c_char_p, c.c_int, c.c_char_p, c.c_uint,
                                                   c.POINTER(c.c_char_p), c.POINTER(c.c_uint)]
        d.WinDivertHelperCompileFilter.restype = c.c_int
        self.d = d

    def check_filter(self, flt: str):
        """None if the filter is valid, otherwise a text with the reason."""
        err, pos = ctypes.c_char_p(), ctypes.c_uint()
        if self.d.WinDivertHelperCompileFilter(flt.encode(), 0, None, 0, ctypes.byref(err), ctypes.byref(pos)):
            return None
        return f"{err.value.decode(errors='replace') if err.value else '?'} (position {pos.value})"

    def open(self, flt: str, priority: int):
        h = self.d.WinDivertOpen(flt.encode(), 0, priority, 0)
        if h in (None, 0, 2 ** 64 - 1):
            code = ctypes.get_last_error()
            why = WD_ERRORS.get(code, "")
            if code == 87:
                why += ": " + str(self.check_filter(flt))
            raise OSError(f"WinDivertOpen failed, error {code} {why}".strip())
        return h

    def recv(self, h, buf, addr) -> int:
        n = ctypes.c_uint(0)
        if not self.d.WinDivertRecv(h, buf, len(buf), ctypes.byref(n), ctypes.byref(addr)):
            raise OSError(ctypes.get_last_error(), "WinDivertRecv")
        return n.value

    def send(self, h, data: bytes, addr):
        if not self.d.WinDivertSend(h, data, len(data), None, ctypes.byref(addr)):
            raise OSError(ctypes.get_last_error(), "WinDivertSend")

    def close(self, h):
        self.d.WinDivertShutdown(h, 3)
        self.d.WinDivertClose(h)


def service_state(name):
    """State of a Windows service: 1 stopped, 3 stop pending, 4 running,
    None - the service does not exist, -1 - unknown (not Windows / no access)."""
    if os.name != "nt":
        return -1
    c = ctypes
    adv = c.WinDLL("advapi32", use_last_error=True)
    adv.OpenSCManagerW.restype = c.c_void_p
    adv.OpenSCManagerW.argtypes = [c.c_wchar_p, c.c_wchar_p, c.c_uint32]
    adv.OpenServiceW.restype = c.c_void_p
    adv.OpenServiceW.argtypes = [c.c_void_p, c.c_wchar_p, c.c_uint32]
    adv.QueryServiceStatus.argtypes = [c.c_void_p, c.c_void_p]
    adv.QueryServiceStatus.restype = c.c_int
    adv.CloseServiceHandle.argtypes = [c.c_void_p]
    scm = adv.OpenSCManagerW(None, None, 1)             # SC_MANAGER_CONNECT
    if not scm:
        return -1
    try:
        svc = adv.OpenServiceW(scm, name, 4)             # SERVICE_QUERY_STATUS
        if not svc:
            return None if c.get_last_error() == 1060 else -1   # ERROR_SERVICE_DOES_NOT_EXIST
        try:
            status = (c.c_uint32 * 7)()                 # SERVICE_STATUS: 7 DWORDs, the 2nd is the state
            return status[1] if adv.QueryServiceStatus(svc, status) else -1
        finally:
            adv.CloseServiceHandle(svc)
    finally:
        adv.CloseServiceHandle(scm)


# ----------------------------------------------------------------- dead addresses + filter
def resolve_dead_ips(names, workers=16, timeout=25):
    """{packed ip: set(names)} for all names (IPv4 and IPv6) through the system resolver."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def one(name):
        try:
            return name, {i[4][0] for i in socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)}
        except OSError:
            return name, set()

    out = {}
    ex = ThreadPoolExecutor(max_workers=workers)
    try:
        for fut in as_completed([ex.submit(one, n) for n in names], timeout=timeout):
            name, ips = fut.result()
            for ip in ips:
                try:
                    a = ipaddress.ip_address(ip.split("%", 1)[0])
                except ValueError:
                    continue
                if a.is_loopback or a.is_unspecified or a.is_link_local or a.is_multicast:
                    continue  # e.g. an old hosts block that still points to 127.0.0.1
                out.setdefault(a.packed, set()).add(name)
    except Exception as e:  # noqa (timeout: use what we have)
        log(f"[divert] DNS: {e!r}, using partial results")
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return out


def _addr_terms(ips, v6: bool):
    """Filter terms for the addresses; collapsed into /24 (/64) ranges when there are too many."""
    field = "ipv6.DstAddr" if v6 else "ip.DstAddr"
    ints = sorted(int.from_bytes(b, "big") for b in ips)
    mk = ipaddress.IPv6Address if v6 else ipaddress.IPv4Address
    terms = [f"{field} == {mk(i)}" for i in ints]
    if len(terms) > FILTER_TERMS_MAX // 2:
        shift = 64 if v6 else 8
        blocks = sorted({i >> shift for i in ints})
        terms = [f"({field} >= {mk(b << shift)} and {field} <= {mk((b << shift) | ((1 << shift) - 1))})" for b in blocks]
    return terms


def build_filter(port: int, dead, drop_quic=True):
    """WinDivert filter string, or None when there is nothing to divert."""
    v4 = [b for b in dead if len(b) == 4]
    v6 = [b for b in dead if len(b) == 16]
    terms = _addr_terms(v4, False) + _addr_terms(v6, True)
    if not terms:
        return None
    terms = terms[:FILTER_TERMS_MAX]
    where = "(" + " or ".join(terms) + ")"      # the address list appears once: the filter has a size limit
    ports = "tcp.DstPort == 443" + (" or udp.DstPort == 443" if drop_quic else "")
    # the last part: replies of the local proxy
    return f"outbound and ((({ports}) and {where}) or tcp.SrcPort == {port})"


class Engine:
    """Keeps the set of dead addresses up to date and runs the packet loop."""

    def __init__(self, port, drop_quic=True):
        self.port, self.drop_quic = port, drop_quic
        self.wd = None
        self.dead = frozenset()
        self.seen = {}
        self.cur = None            # (handle, filter)
        self.prio = WD_PRIORITY
        self.stop_ev = threading.Event()
        self.lock = threading.Lock()
        self.ok = False
        self.released = False      # we let go of the driver because somebody is stopping it
        self.released_at = 0.0

    def is_dead(self, ip_text: str) -> bool:
        b = pack_ip(ip_text)
        return b is not None and b in self.dead

    def start(self):
        try:
            self.wd = WinDivert()
        except OSError as e:
            log(f"[divert] ERROR: {e}")
            return False
        threading.Thread(target=self._resolver, daemon=True, name="gv-resolver").start()
        threading.Thread(target=self._watch, daemon=True, name="gv-watch").start()
        return True

    def stop(self):
        self.stop_ev.set()
        with self.lock:
            if self.cur:
                try:
                    self.wd.close(self.cur[0])
                except Exception:
                    pass
                self.cur = None

    def _resolver(self):
        while not self.stop_ev.is_set():
            try:
                names = load_blocked_hosts()
                found = resolve_dead_ips(names)
                now = time.monotonic()
                for b in found:
                    self.seen[b] = now
                for b, t in list(self.seen.items()):
                    if now - t > DEAD_KEEP:
                        del self.seen[b]
                new = frozenset(self.seen)
                if new != self.dead:
                    added = new - self.dead
                    self.dead = new
                    log(f"[divert] dead addresses: {len(new)} (from {len(names)} names)"
                        + (": " + ", ".join(unpack_ip(b) for b in sorted(added))[:300] if added and len(added) <= 12 else ""))
                self._reopen()
            except Exception as e:  # noqa
                log(f"[divert] ERROR in the resolver: {e!r}")
            self.stop_ev.wait(DEAD_REFRESH if self.dead else 30)

    def _release(self):
        with self.lock:
            self.released = True
            self.released_at = time.monotonic()
            old, self.cur = self.cur, None
        if old:
            try:
                self.wd.close(old[0])
            except Exception:
                pass

    def _watch(self):
        """zapret's "Remove Services" stops the zapret service and then runs "net stop WinDivert". The driver
        cannot unload while we hold a handle, so that command hangs or prints errors. So we let go of the
        handle as soon as the zapret service stops (or somebody asks the driver to stop) - the driver then
        unloads by itself - and take it back several seconds later."""
        warned = 0.0
        zap_prev = None
        while not self.stop_ev.wait(SVC_POLL):
            try:
                st = service_state(SVC_NAME)
                zap = service_state(ZAPRET_SVC)
                zap_stopping = zap_prev == SVC_RUNNING and zap in (SVC_STOPPED, SVC_STOP_PENDING, None)
                zap_prev = zap
                busy = st == SVC_STOP_PENDING or zap == SVC_STOP_PENDING
                if not self.released:
                    if self.cur and (st == SVC_STOP_PENDING or zap_stopping):
                        log("[divert] zapret service / WinDivert is being stopped: releasing the driver, "
                            "will reconnect in a few seconds")
                        self._release()
                elif busy:
                    self.released_at = time.monotonic()
                elif time.monotonic() - self.released_at >= SVC_REGRAB_DELAY:
                    with self.lock:
                        self.released = False
                    if self._reopen(quiet=True):
                        log("[divert] reconnected to WinDivert")
                    elif self.dead:
                        with self.lock:
                            self.released = True          # not possible yet (the old service is still going away)
                            self.released_at = time.monotonic() - SVC_REGRAB_DELAY + 1
                        if time.monotonic() - warned > 30:
                            warned = time.monotonic()
                            log("[divert] waiting to reconnect to WinDivert...")
            except Exception as e:  # noqa
                log(f"[divert] ERROR in the watcher: {e!r}")

    def _reopen(self, quiet=False) -> bool:
        flt = build_filter(self.port, self.dead, self.drop_quic)
        with self.lock:
            if self.released:
                return False
            if self.stop_ev.is_set() or (self.cur and self.cur[1] == flt) or (not self.cur and flt is None):
                return True
            old, new = self.cur, None
            if flt is not None:
                self.prio += 1
                try:
                    h = self.wd.open(flt, self.prio)
                except OSError as e:
                    if not quiet:
                        log(f"[divert] ERROR: {e}")
                    return False
                new = (h, flt)
                threading.Thread(target=self._loop, args=(h,), daemon=True, name="gv-divert").start()
                log(f"[divert] active, {len(self.dead)} addresses")
                self.ok = True
            self.cur = new
            if old:
                try:
                    self.wd.close(old[0])   # its loop ends by itself
                except Exception:
                    pass
        return True

    def _loop(self, h):
        buf = ctypes.create_string_buffer(65600)
        addr = WdAddress()
        while not self.stop_ev.is_set():
            try:
                n = self.wd.recv(h, buf, addr)
            except OSError as e:
                code = e.args[0] if e.args else 0
                if code in (6, 232, 995) or self.cur is None or self.cur[0] != h:
                    return          # handle closed
                log(f"[divert] recv error {code}")
                time.sleep(0.05)
                continue
            raw = ctypes.string_at(buf, n)
            try:
                out = self.process(bytearray(raw), addr)
            except Exception as e:  # noqa
                log(f"[divert] packet error {e!r} - passed unchanged")
                out = [(raw, addr)]
            for data, a in out:
                try:
                    self.wd.send(h, bytes(data), a)
                except OSError as e:
                    log(f"[divert] send error {e.args[0] if e.args else e}")

    def process(self, pkt: bytearray, addr: WdAddress):
        """-> list of (packet, address) to inject; an empty list drops the packet."""
        p = parse_packet(pkt)
        if p is None or not addr.outbound:
            return [(pkt, addr)]
        if p.proto == 17:
            if self.drop_quic and p.dport == 443 and p.dst in self.dead:
                return []
            return [(pkt, addr)]
        if p.dport == 443 and p.dst in self.dead:
            if p.flags & SYN and not p.flags & ACK:
                log(f"[divert] {unpack_ip(p.dst)}:443 -> local proxy")
            reflect_to_proxy(pkt, p, self.port)
            addr.make_inbound_valid()
            return [(pkt, addr)]
        if p.sport == self.port and p.dst in self.dead:
            reflect_from_proxy(pkt, p)
            addr.make_inbound_valid()
            return [(pkt, addr)]
        return [(pkt, addr)]


# ----------------------------------------------------------------- proxy
def _tune(writer):
    """TCP_NODELAY + keepalive: dead peers are noticed instead of hanging forever."""
    try:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        pass


class Proxy:
    def __init__(self, args, engine=None):
        self.args = args
        self.engine = engine  # knows the dead addresses (None = no WinDivert, e.g. tests)
        self.dns_cache = {}   # host -> (expires_at, [ips])
        self.bad = {}         # (host, ip) -> time until which it is deprioritised
        self._file_cache = {}
        self.up_ctx = ssl.create_default_context()
        self.up_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.up_ctx.set_alpn_protocols(["http/1.1"])
        if args.insecure_upstream:
            self.up_ctx.check_hostname = False
            self.up_ctx.verify_mode = ssl.CERT_NONE

    def _cached(self, path: Path, loader):
        """Re-reads the file only when its modification time changes - edits are picked up on the fly."""
        try:
            mtime = path.stat().st_mtime_ns
        except OSError:
            mtime = None
        hit = self._file_cache.get(path)
        if hit is None or hit[0] != mtime:
            hit = (mtime, loader())
            self._file_cache[path] = hit
        return hit[1]

    def pick_upstreams(self, host: str, target: str) -> list:
        """Ordered candidates: ALL working nodes from mn= (the link is issued only for them), then the
        --fallback-host. Nodes from blocked.txt (and their family) are skipped."""
        m = HOST_RE.match(host or "")
        out = []
        if m:
            rr, own = m.group(1), m.group(2).lower()
            dead, dead_hosts, families = self._cached(BLOCKED_FILE, load_dead)
            mn = parse_qs(urlsplit(target).query).get("mn", [""])[0]
            for node in mn.split(","):
                node = node.strip().lower()
                if (not node or node == own or node in dead
                        or any(node.startswith(f + "-") for f in families)):
                    continue
                # the rr of the original host first; if that exact name is listed as dead, another rr of the node
                names = [f"rr{rr}---{node}.googlevideo.com"] + [
                    f"rr{k}---{node}.googlevideo.com" for k in ALT_RR_POOL if str(k) != rr]
                name = next((n for n in names if n not in dead_hosts), None)
                if name:
                    out.append(name)
        # The fallback node can only serve requests that are not tied to a node (generate_204 and the like).
        # A /videoplayback link is issued for the nodes listed in mn=; any other node answers 400, so for
        # videoplayback there is no fallback: the connection is closed and the player switches host itself.
        if urlsplit(target).path != "/videoplayback" or self.args.fallback_video:
            out.append(self.args.fallback_host)
        return list(dict.fromkeys(out))

    def group(self, name: str) -> list:
        """The node's own name first, then other rrN names of the SAME node. Different rrN names of a node
        resolve to different IP addresses, and one of them may be unreachable (blackholed) while the others
        work - exactly what happened with rr5---sn-n8v7kn7d (timeouts) vs rr2---sn-n8v7kn7d (fine)."""
        m = HOST_RE.match(name or "")
        if self.args.upstream_ip or not m or name == self.args.fallback_host:
            return [name]
        _, dead_hosts, _ = self._cached(BLOCKED_FILE, load_dead)
        node = m.group(2).lower()
        alts = [f"rr{k}---{node}.googlevideo.com" for k in ALT_RR_POOL if str(k) != m.group(1)]
        return [name] + [a for a in alts if a not in dead_hosts][:ALT_PER_NODE]

    @staticmethod
    def _is_loopback(ip: str) -> bool:
        return ip.startswith("127.")

    def _is_dead_ip(self, ip: str) -> bool:
        """An address that WinDivert diverts to us: connecting to it would loop back into the proxy."""
        return self.engine is not None and self.engine.is_dead(ip)

    async def resolve(self, host: str) -> list:
        """All IPv4 addresses of the node (cached for DNS_TTL)."""
        if self.args.upstream_ip:
            return [self.args.upstream_ip]
        hit = self.dns_cache.get(host)
        if hit and hit[0] > time.monotonic():
            return list(hit[1])
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM), timeout=5
        )
        ips = list(dict.fromkeys(i[4][0] for i in infos))
        self.dns_cache[host] = (time.monotonic() + DNS_TTL, ips)
        return ips

    async def _race_connect(self, plan):
        """Hedged connect over a plan of (name, ip) pairs: a new attempt is started every HEDGE_DELAY seconds
        (or at once if the previous one failed) and the first connection that completes the TLS handshake
        wins. A lost SYN or one blackholed IP therefore costs ~1 s instead of a whole failed request.
        Returns (reader, writer, name, ip)."""
        pending, started, last_err, nxt = {}, {}, None, 0
        deadline = time.monotonic() + UP_CONNECT_TIMEOUT
        winner = None
        try:
            while winner is None:
                if nxt < len(plan):
                    name, ip = plan[nxt]
                    t = asyncio.ensure_future(asyncio.open_connection(
                        ip, self.args.upstream_port, ssl=self.up_ctx, server_hostname=name))
                    pending[t] = plan[nxt]
                    started[t] = time.monotonic()
                    nxt += 1
                left = deadline - time.monotonic()
                if not pending or left <= 0:
                    break
                wait = min(HEDGE_DELAY, left) if nxt < len(plan) else left
                done, _ = await asyncio.wait(list(pending), timeout=wait, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    name, ip = pending.pop(t)
                    try:
                        conn = t.result()
                    except Exception as e:  # noqa
                        last_err = e
                        continue
                    if winner is None:
                        winner = (conn[0], conn[1], name, ip)
                    else:
                        self._close(conn[1])  # two attempts finished together: keep one
        finally:
            now = time.monotonic()
            for t, pair in pending.items():
                t.cancel()
                if winner is not None and now - started[t] >= HEDGE_DELAY * 0.9:
                    self.bad[pair] = now + BAD_TTL  # slower than the winner: try it last next time
            for r in await asyncio.gather(*pending, return_exceptions=True):
                if isinstance(r, tuple):
                    self._close(r[1])
        if winner is None:
            raise last_err or asyncio.TimeoutError()
        return winner

    async def _resolve_quiet(self, name):
        try:
            return await self.resolve(name)
        except (OSError, asyncio.TimeoutError):
            return []

    async def connect_upstream(self, candidates: list, tried: set):
        """Walks the candidate nodes until one connects. Returns (reader, writer, up_host, ip) or None.
        For each node the attempts are spread over its own name and a few other rrN names (other IPs).
        Every candidate it actually tries is added to `tried`. A node whose addresses all failed recently is
        skipped while there are other options (and not counted as tried); as the last option it is tried."""
        now = time.monotonic()
        for idx, cand in enumerate(candidates):
            last = idx == len(candidates) - 1
            names = self.group(cand)
            resolved = await asyncio.gather(*(self._resolve_quiet(n) for n in names))
            ipmap = {}
            for n, ips in zip(names, resolved):
                ips = [ip for ip in ips if self.args.upstream_ip or not (self._is_loopback(ip) or self._is_dead_ip(ip))]
                if ips:
                    ipmap[n] = ips
                elif n == cand:
                    log(f"{n}: no usable address (does not resolve, points to 127.x, or is a dead node address)")
            if not ipmap:
                tried.add(cand)
                continue
            primary = [(n, ipmap[n][0]) for n in names if n in ipmap]
            secondary = [(n, ipmap[n][1]) for n in names if n in ipmap and len(ipmap[n]) > 1]
            plan = primary + secondary
            fresh = [p for p in plan if self.bad.get(p, 0) <= now]
            if not fresh:
                if not last:
                    log(f"skipping {cand}: failed recently")
                    continue
                fresh = plan  # the last resort: try even the ones marked bad
            plan = fresh + [p for p in plan if p not in fresh]
            plan = list(itertools.islice(itertools.cycle(plan), UP_ATTEMPTS))  # a short plan is repeated
            tried.add(cand)
            t_conn = time.monotonic()
            try:
                ur, uw, up_host, ip = await self._race_connect(plan)
            except (OSError, ssl.SSLError, asyncio.TimeoutError) as e:
                for p in plan:
                    self.bad[p] = time.monotonic() + BAD_TTL
                for n in names:
                    self.dns_cache.pop(n, None)  # maybe the address changed - resolve again next time
                shown = ", ".join("%s[%s]" % (n.split(".")[0], p_ip) for n, p_ip in plan)
                log(f"UPSTREAM ERROR {cand}: {e!r} (tried {shown})")
                continue
            self.bad.pop((up_host, ip), None)
            if time.monotonic() - t_conn > 1.0 or up_host != cand:
                log(f"connect to {cand}: {time.monotonic() - t_conn:.1f}s, connected via {up_host} [{ip}]")
            _tune(uw)
            return ur, uw, up_host, ip
        return None

    # ------------------------------------------------------------ one request/response exchange
    @staticmethod
    async def read_resp_head(ur):
        """Response head from the node, or None if it closed / reset / stayed silent."""
        try:
            return await asyncio.wait_for(ur.readuntil(b"\r\n\r\n"), RESP_HEAD_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, OSError):
            return None

    async def exchange(self, head, candidates, body, stream, reuse):
        """Sends one request and returns (resp_head, ur, uw, up_host) or None.
        - the node is chosen per request (from ITS mn=), not once per connection;
        - a node that answers 400/403/5xx, or does not answer at all, is replaced by the next candidate
          (only while the request can be replayed: no huge/chunked body);
        - a stale keep-alive connection is silently replaced by a fresh one;
        - if every candidate is bad, the last bad answer is passed to the browser as is."""
        replayable = stream is None
        tried, best, use = set(), None, reuse
        while True:
            fresh = use is None
            if fresh:
                remaining = [c for c in candidates if c not in tried]
                conn = await self.connect_upstream(remaining, tried) if remaining else None
                if conn is None:
                    break
                ur, uw, up_host, _ip = conn
            else:
                ur, uw, up_host = use
                use = None
            resp = None
            try:
                uw.write(rewrite_host(head, up_host))
                if body:
                    uw.write(body)
                await uw.drain()
            except (OSError, asyncio.TimeoutError):
                pass
            else:
                if stream is not None:
                    await stream(uw)  # client-side errors propagate and close the connection
                resp = await self.read_resp_head(ur)
            if resp is None:
                log(f"no answer from {up_host}" + ("" if fresh else " (stale keep-alive, reconnecting)"))
                self._close(uw)
                if not replayable:
                    break
                continue
            # it has answered: a retry must go to a different node
            tried.add(next((c for c in candidates if up_host in self.group(c)), up_host))
            status = parse_status(resp)
            if status in RETRY_STATUS or status >= 500:
                if replayable and any(c not in tried for c in candidates):
                    log(f"{up_host} answered {status} -> trying another node")
                    if best:
                        self._close(best[2])
                    best = (resp, ur, uw, up_host)
                    continue
            if best:
                self._close(best[2])
            return resp, ur, uw, up_host
        return best

    @staticmethod
    def _close(w):
        try:
            w.close()
        except Exception:
            pass

    async def relay_response(self, head, ur, writer, method) -> bool:
        """Forwards the response to the browser. True = the connection may be reused."""
        status = parse_status(head)
        # Nodes advertise HTTP/3 via Alt-Svc. Chrome remembers it for days and then tries QUIC (UDP 443) towards
        # 127.0.0.1, where nobody listens. The proxy speaks only TCP, so the hint is dropped.
        head = re.sub(rb"(?im)^alt-svc:[^\r\n]*\r\n", b"", head)
        _, _, h = parse_head(head)
        writer.write(head)
        reusable = "close" not in h.get("connection", "").lower()
        if method == "HEAD" or status in (204, 304) or 100 <= status < 200:
            await writer.drain()
            return reusable
        if "chunked" in h.get("transfer-encoding", "").lower():
            await relay_chunked(ur, writer, IDLE_TIMEOUT)
            return reusable
        if "content-length" in h:
            await copy_exact(ur, writer, int(h["content-length"] or 0), IDLE_TIMEOUT)
            return reusable
        while True:  # no length: the body ends when the node closes the connection
            data = await asyncio.wait_for(ur.read(65536), IDLE_TIMEOUT)
            if not data:
                break
            writer.write(data)
            await writer.drain()
        return False

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        cur = None  # idle upstream connection kept for the next request: (reader, writer, up_host)
        _tune(writer)
        peer = writer.get_extra_info("peername")
        if self.engine is not None and not (peer and self.engine.is_dead(peer[0])):
            # with WinDivert the peer address is the original destination: only dead nodes are redirected here
            log(f"refused a connection from {peer[0] if peer else '?'} (not a redirected address)")
            self._close(writer)
            return
        try:
            while True:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IDLE_TIMEOUT)
                t_req = time.monotonic()
                method, target, headers = parse_head(head)
                host = headers.get("host", "").split(":")[0]
                chunked = "chunked" in headers.get("transfer-encoding", "").lower()
                length = int(headers.get("content-length", "0") or 0)
                body, stream = b"", None
                if chunked or length > MAX_BUFFERED_BODY:
                    async def stream(uw, chunked=chunked, length=length):
                        if chunked:
                            await relay_chunked(reader, uw, IDLE_TIMEOUT)
                        else:
                            await copy_exact(reader, uw, length, IDLE_TIMEOUT)
                elif length:
                    body = await asyncio.wait_for(reader.readexactly(length), IDLE_TIMEOUT)

                candidates = self.pick_upstreams(host, target)
                if not candidates:
                    mn = parse_qs(urlsplit(target).query).get("mn", [""])[0]
                    log(f"{host}: no usable node in mn={mn!r} for {target[:40]} -> closing, the player will switch host itself")
                    break
                reuse = cur if (cur and stream is None and cur[2] in self.group(candidates[0])) else None
                if cur and reuse is None:
                    self._close(cur[1])
                cur = None

                res = await self.exchange(head, candidates, body, stream, reuse)
                if res is None:
                    log(f"no upstream for {host}: every candidate failed (the browser will retry)")
                    break
                resp, ur, uw, up_host = res
                q = parse_qs(urlsplit(target).query)
                log(f"{host} -> {up_host} {method} {urlsplit(target).path} mn={q.get('mn', [''])[0]} "
                    f"=> {parse_status(resp)} {time.monotonic() - t_req:.2f}s"
                    + (" (kept-alive)" if reuse is not None and ur is reuse[0] else ""))
                if not await self.relay_response(resp, ur, writer, method):
                    self._close(uw)
                    break
                cur = (ur, uw, up_host)
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError, asyncio.TimeoutError):
            pass
        except Exception as e:  # noqa
            log(f"connection error: {e!r}")
        finally:
            if cur:
                self._close(cur[1])
            self._close(writer)


async def run(args):
    engine = None
    if not args.no_divert:
        if not is_admin():
            log("[divert] ERROR: administrator rights are required (run via the .bat or the installed task)")
            return 1
        need_windivert()
        engine = Engine(args.port, drop_quic=not args.keep_quic)
        if not engine.start():
            return 1
    asyncio.get_running_loop().set_exception_handler(
        lambda loop, c: log(f"asyncio: {c.get('message')} {c.get('exception')!r}"))
    if not (LEAF_CRT.exists() and LEAF_KEY.exists()):
        log("No certificates. First run: gv_proxy.py gen (or the install item in the .bat)")
        return 1
    ensure_config_files()
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.minimum_version = ssl.TLSVersion.TLSv1_2
    sctx.set_alpn_protocols(["http/1.1"])  # the browser will speak HTTP/1.1
    sctx.load_cert_chain(str(LEAF_CRT), str(LEAF_KEY))

    def _hello(sslobj, name, ctx):  # every incoming TLS connection; no request line after it = the browser aborted
        try:
            log(f"hello {name}")
        except Exception:
            pass
    sctx.sni_callback = _hello
    proxy = Proxy(args, engine)
    servers = []
    for addr in (args.listen or DEFAULT_LISTEN):
        try:
            servers.append(await asyncio.start_server(
                proxy.handle, addr, args.port, ssl=sctx, backlog=511, limit=2 ** 18))
        except OSError as e:
            log(f"Could not bind {addr}:{args.port}: {e}. "
                f"The port may be used by another program or the proxy is already running "
                f"(in a window or in the background); try another one with --port.")
    if not servers:
        return 1
    log(f"Proxy listening on {', '.join(str(s.sockets[0].getsockname()[0]) for s in servers)}:{args.port}. "
        f"Node is taken from mn= of the link, fallback: {args.fallback_host}. Close the window to stop.")
    try:
        await asyncio.gather(*(s.serve_forever() for s in servers))
    finally:
        if engine:
            engine.stop()
    return 0


def main():
    global LOG_TO_FILE
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["gen", "run", "setup", "install", "uninstall", "uninstall-autostart", "stop", "check"])
    ap.add_argument("--keep-quic", action="store_true", help="do not drop QUIC (UDP/443) to the dead nodes")
    ap.add_argument("--no-divert", action="store_true", help="run only the TLS proxy, without WinDivert (tests)")
    ap.add_argument("--listen", action="append", help="address to listen on, may be repeated (default: 0.0.0.0 and ::)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="local port of the proxy")
    ap.add_argument("--fallback-host", default="rr15---sn-n8v7kne6.googlevideo.com")
    ap.add_argument("--upstream-ip", default=None, help="force the upstream IP (for debugging)")
    ap.add_argument("--upstream-port", type=int, default=443)
    ap.add_argument("--fallback-video", action="store_true",
                    help="also send /videoplayback to --fallback-host when mn= gives no working node (it normally answers 400)")
    ap.add_argument("--insecure-upstream", action="store_true", help="do not verify the upstream certificate (tests only)")
    ap.add_argument("--log", action="store_true", help="write the log to gv_proxy.log (enabled automatically without a console)")
    args = ap.parse_args()
    LOG_TO_FILE = args.log or sys.stdout is None
    if args.cmd == "gen":
        gen_certs()
        return 0
    if args.cmd == "setup":
        cmd_setup(args.port)
        return 0
    if args.cmd == "install":
        cmd_install(args.port)
        return 0
    if args.cmd == "check":
        cmd_check(args)
        return 0
    if args.cmd == "uninstall":
        cmd_uninstall()
        return 0
    if args.cmd == "uninstall-autostart":
        cmd_uninstall_autostart()
        return 0
    if args.cmd == "stop":
        need_admin()
        stop_proxy()
        return 0
    try:
        return asyncio.run(run(args)) or 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        log("Fatal error:\n" + traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(main())
