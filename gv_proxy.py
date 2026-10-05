#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gv_proxy.py - local proxy that replaces dead googlevideo nodes
(rrN---sn-pivhx-*.googlevideo.com) with a working node taken from the mn= parameter of the link itself.

Configuration: blocked.txt next to the script - full addresses of the nodes to redirect
(they go into hosts). Where to redirect, the proxy decides itself - from the mn= parameter in the link.

The browser (via hosts) connects to 127.0.0.1:443, the proxy:
  1) terminates TLS with its own *.googlevideo.com certificate;
  2) picks a working node from mn= (or --fallback-host);
  3) connects to it (its SNI + Host) and rewrites the Host header;
  4) pipes bytes back and forth.

Commands (anything that changes the system needs administrator rights; the .bat requests them itself):
  gen                 - create certificates (the CA key is discarded immediately)
  run                 - run the proxy in this window
  setup               - certificates + trusted root + hosts entries
  install             - setup + background run without a window + autostart at Windows logon
  uninstall-autostart - stop the proxy and remove autostart (hosts and certificate stay)
  uninstall           - remove everything the script installed (only its own hosts entries, its own certificate)
  stop                - stop the running proxy
"""
import argparse
import asyncio
import base64
import ctypes
import datetime
import hashlib
import itertools
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import traceback
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

HERE = Path(__file__).resolve().parent
CA_CER = HERE / "gv_ca.cer"        # DER, installed into the trusted roots
LEAF_CRT = HERE / "gv_leaf.crt"    # certificate for *.googlevideo.com
LEAF_KEY = HERE / "gv_leaf.key"    # its key
HOST_RE = re.compile(r"^rr(\d+)---(sn-[a-z0-9-]+)\.googlevideo\.com$", re.I)
BLOCKED_FILE = HERE / "blocked.txt"
DEFAULT_BLOCKED = """# Dead googlevideo nodes that should be redirected.
# One per line (# starts a comment). Accepted forms:
#   rr3---sn-pivhx-n8vs.googlevideo.com   - one exact address
#   rr*---sn-pivhx-n8vs.googlevideo.com   - the same node on every rr1..rr30
#   sn-pivhx-n8vs                         - short form of the line above
# After changing this file, run menu item 1 (Install) again - it updates hosts.
""" + "".join(
    f"rr{_r}---sn-pivhx-{_s}.googlevideo.com\n"
    for _r in range(1, 31) for _s in ("n8vs", "n8vz", "n8v6", "n8vd")
)

RR_MAX = 30   # rr* in blocked.txt expands to rr1 .. rr30
LOG_FILE = HERE / "gv_proxy.log"
TASK_NAME = "GV Proxy"
CA_NAME = "GV Local CA (googlevideo.com only)"
HOSTS = Path(os.environ.get("GV_HOSTS_FILE") or
             Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts")
HOSTS_BACKUP = HOSTS.with_name(HOSTS.name + ".gv-backup")
BEGIN_RE = re.compile(r"^#\s*GV-(PROXY|BLOCK)-BEGIN\s*$")
END_RE = re.compile(r"^#\s*GV-(PROXY|BLOCK)-END\s*$")
BLOCK_LINE_RE = re.compile(r"^(127\.0\.0\.1|0\.0\.0\.0|::1)\s+[a-z0-9.-]+\.googlevideo\.com$", re.I)
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
DEFAULT_LISTEN = ["127.0.0.1", "::1"]
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
    """List of host names for hosts, from blocked.txt (rr* / bare node names are expanded)."""
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
    if os.environ.get("GV_HOSTS_FILE") or is_admin():
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


def flush_dns():
    run_quiet(["ipconfig", "/flushdns"])


# --- hosts: we touch ONLY the block between the markers and only lines written by the script itself
def _strip_block(text: str):
    """Removes the markers and lines like "IP host.googlevideo.com" inside the block (the block is built
    from blocked.txt, so the list may have changed). Everything else (your entries outside the block,
    any other lines, comments, encoding) stays byte for byte."""
    out, kind, removed = [], None, 0
    for line in text.split("\n"):
        st = line.strip()
        m = BEGIN_RE.match(st)
        if m:
            kind, removed = m.group(1), removed + 1
            continue
        if END_RE.match(st):
            kind, removed = None, removed + 1
            continue
        if kind:
            norm = " ".join(st.split()).lower()
            if BLOCK_LINE_RE.match(norm):  # inside our block - only lines like "IP *.googlevideo.com"
                removed += 1
                continue
        out.append(line)
    return "\n".join(out), removed


def _read_hosts() -> str:
    raw = HOSTS.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in raw:
        print("hosts is saved as UTF-16 or contains binary data. The script will not touch it: "
              "re-save the file as ANSI/UTF-8 and run the command again.")
        sys.exit(1)
    return raw.decode("latin-1")  # latin-1 = lossless for any bytes


def _backup_hosts():
    """One copy of the very first original + a snapshot before every change (the last 5 are kept)."""
    try:
        if not HOSTS_BACKUP.exists():
            shutil.copy2(HOSTS, HOSTS_BACKUP)
        snap = HOSTS.with_name(f"{HOSTS.name}.gv-{time.strftime('%Y%m%d-%H%M%S')}.bak")
        shutil.copy2(HOSTS, snap)
        for old in sorted(HOSTS.parent.glob(HOSTS.name + ".gv-*.bak"))[:-5]:
            try:
                old.unlink()
            except OSError:
                pass
    except OSError as e:
        print("Could not make a backup of hosts:", e)
        sys.exit(1)


def _overwrite(data: bytes):
    # write from the start and cut the tail afterwards: the file is never empty in the middle of the operation
    with open(HOSTS, "r+b") as f:
        f.seek(0)
        f.write(data)
        f.truncate()


def _write_hosts(text: str):
    new = text.encode("latin-1")
    old = HOSTS.read_bytes()
    if new == old:
        return
    _backup_hosts()
    err = None
    for _ in range(3):  # an antivirus or another program may hold the file for a moment
        try:
            _overwrite(new)
            if HOSTS.read_bytes() == new:
                return
            err = "the content read back does not match"
        except OSError as e:
            err = e
        time.sleep(0.5)
    try:
        _overwrite(old)  # put the previous content back
    except OSError:
        pass
    print(f"Could not write hosts ({err}). The previous content was restored; copies: {HOSTS_BACKUP.name}, {HOSTS.name}.gv-*.bak")
    sys.exit(1)


def hosts_add():
    text, _ = _strip_block(_read_hosts())
    nl = "\r\n" if ("\r\n" in text or not text) else "\n"
    if text and not text.endswith("\n"):
        text += nl
    hosts = load_blocked_hosts()
    if not hosts:
        print(f"Warning: {BLOCKED_FILE.name} has no valid nodes - nothing to redirect.")
    # ::1 too: otherwise the browser may take the IPv6 address of the dead node and bypass the proxy
    lines = ["# GV-PROXY-BEGIN"] + [f"{ip} {h}" for h in hosts for ip in ("127.0.0.1", "::1")] + ["# GV-PROXY-END"]
    _write_hosts(text + nl.join(lines) + nl)
    flush_dns()
    print(f"hosts: addresses written from {BLOCKED_FILE.name}: {len(hosts)}.")


def hosts_remove():
    old = _read_hosts()
    new, removed = _strip_block(old)
    if new != old:
        _write_hosts(new)
        flush_dns()
    print(f"hosts: script lines removed: {removed}. Everything else untouched.")


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


def autostart_on():
    pyw = Path(sys.executable).with_name("pythonw.exe")
    if not pyw.exists():
        print("pythonw.exe not found next to", sys.executable, "- it is required to run without a window.")
        sys.exit(1)
    script = str(HERE / "gv_proxy.py")
    ps = f"""
$ErrorActionPreference = 'Stop'
$me  = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$act = New-ScheduledTaskAction -Execute {_psq(pyw)} -Argument {_psq('"' + script + '" run --log')} -WorkingDirectory {_psq(HERE)}
$trg = New-ScheduledTaskTrigger -AtLogOn -User $me
$pri = New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive -RunLevel Limited
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
    code, out, err = powershell(f"Start-ScheduledTask -TaskName {_psq(TASK_NAME)}")
    if code != 0:
        print("Could not start the task:", err or out)
        sys.exit(1)
    for _ in range(10):
        time.sleep(0.5)
        try:
            socket.create_connection(("127.0.0.1", 443), timeout=1).close()
            print("Proxy is running in the background (127.0.0.1:443).")
            return
        except OSError:
            pass
    print(f"Proxy does not respond on 127.0.0.1:443. See the log: {LOG_FILE}")


# --- scenarios
def cmd_setup():
    need_admin()
    ensure_config_files()
    ensure_certs()
    cert_add()
    hosts_add()


def cmd_install():
    need_admin()
    stop_proxy()
    cmd_setup()
    autostart_on()
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
    hosts_remove()
    cert_remove()
    for f in (CA_CER, LEAF_CRT, LEAF_KEY, LOG_FILE, LOG_FILE.with_suffix(".log.old")):
        try:
            f.unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            print("Could not delete", f.name, e)
    print("Done: autostart, hosts entries (only the script's own), certificate and keys removed.")


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
    def __init__(self, args):
        self.args = args
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
                ips = [ip for ip in ips if self.args.upstream_ip or not self._is_loopback(ip)]
                if ips:
                    ipmap[n] = ips
                elif n == cand:
                    log(f"{n}: no usable address (does not resolve, or it points to 127.x)")
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
    asyncio.get_running_loop().set_exception_handler(
        lambda loop, c: log(f"asyncio: {c.get('message')} {c.get('exception')!r}"))
    proxy = Proxy(args)
    servers = []
    for addr in (args.listen or DEFAULT_LISTEN):
        try:
            servers.append(await asyncio.start_server(
                proxy.handle, addr, args.port, ssl=sctx, backlog=511, limit=2 ** 18))
        except OSError as e:
            log(f"Could not bind {addr}:{args.port}: {e}. "
                f"Port 443 may be used by another program (IIS, Docker, a web server) "
                f"or the proxy is already running (in a window or in the background).")
    if not servers:
        return 1
    log(f"Proxy listening on {', '.join(str(s.sockets[0].getsockname()[0]) for s in servers)}:{args.port}. "
        f"Node is taken from mn= of the link, fallback: {args.fallback_host}. Close the window to stop.")
    await asyncio.gather(*(s.serve_forever() for s in servers))
    return 0


def main():
    global LOG_TO_FILE
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["gen", "run", "setup", "install", "uninstall", "uninstall-autostart", "stop"])
    ap.add_argument("--listen", action="append", help="address to listen on, may be repeated (default: 127.0.0.1 and ::1)")
    ap.add_argument("--port", type=int, default=443)
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
        cmd_setup()
        return 0
    if args.cmd == "install":
        cmd_install()
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
