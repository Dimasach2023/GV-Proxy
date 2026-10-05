@echo off
title GV proxy setup

rem --- requests administrator rights by itself
fltmc >nul 2>&1 && goto :admin
set "SELF=%~f0"
echo Requesting administrator rights...
powershell -NoProfile -Command "try { Start-Process -FilePath $env:SELF -Verb RunAs -ErrorAction Stop } catch { exit 1 }"
if errorlevel 1 (
    echo Administrator rights were not granted. The script cannot work without them.
    pause
)
exit /b

:admin
cd /d "%~dp0"
mode con: cols=110 lines=32 >nul 2>&1

if not exist "gv_proxy.py" (
    echo Put gv_proxy.py in the same folder as this file.
    pause
    exit /b 1
)

call :findpy
if not defined PY call :getpy
if not defined PY (
    echo.
    echo Could not install Python 3 automatically.
    echo Install it manually from https://www.python.org/downloads/ ^(tick Add python.exe to PATH^) and run this file again.
    pause
    exit /b 1
)

:menu
title GV proxy setup
cls
echo.
echo  1 - Install: background mode without a window + autostart at Windows logon
echo  2 - Uninstall: stop the proxy and remove autostart
echo  3 - Certificate and hosts + run the proxy in a window ^(test mode^)
echo  4 - Only run the proxy in a window
echo  5 - Remove everything ^(autostart, hosts, certificate, files^)
echo  6 - Exit
echo.
choice /c 123456 /n /m "Choice: "
if errorlevel 6 exit /b 0
if errorlevel 5 goto uninstall_all
if errorlevel 4 goto start_window
if errorlevel 3 goto setup_window
if errorlevel 2 goto uninstall_autostart
goto install

:deps
%PY% -c "import cryptography" >nul 2>&1 && exit /b 0
echo Installing the cryptography library...
%PY% -m pip install --quiet cryptography
if errorlevel 1 (
    echo Failed to install cryptography. Check your internet connection.
    pause
    exit /b 1
)
exit /b 0

:install
cls
call :deps || goto menu
%PY% gv_proxy.py install
echo.
pause
goto menu

:uninstall_autostart
cls
%PY% gv_proxy.py uninstall-autostart
echo.
pause
goto menu

:setup_window
cls
call :deps || goto menu
%PY% gv_proxy.py setup
if errorlevel 1 (
    echo.
    pause
    goto menu
)
echo.
echo Certificate and hosts are ready. Fully restart Chrome or Edge ^(Firefox does not use the system certificates^).
goto start_window

:start_window
%PY% gv_proxy.py stop >nul 2>&1
echo Starting the proxy in a separate window. Do not close it while you watch YouTube.
start "GVP-run" cmd /k %PY% "%~dp0gv_proxy.py" run
echo.
pause
goto menu

:uninstall_all
cls
%PY% gv_proxy.py uninstall
echo.
pause
goto menu

rem ===================== helpers =====================

:findpy
set "PY="
where py >nul 2>&1 && py -3 --version >nul 2>&1 && set "PY=py -3"
if defined PY exit /b 0
where python >nul 2>&1 && python --version >nul 2>&1 && set "PY=python"
exit /b 0

:refreshpath
rem pick up the PATH changed by the Python installer without restarting this window
for /f "usebackq delims=" %%P in (`powershell -NoProfile -Command "[Environment]::ExpandEnvironmentVariables([Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User'))"`) do set "PATH=%%P;%PATH%"
exit /b 0

:getpy
echo.
echo Python 3 not found. Installing it automatically...

rem --- attempt 1: winget
where winget >nul 2>&1
if not errorlevel 1 (
    echo Trying winget...
    winget install -e --id Python.Python.3.12 --scope machine --silent --accept-package-agreements --accept-source-agreements
    call :refreshpath
    call :findpy
)
if defined PY exit /b 0

rem --- attempt 2: download the installer from python.org
set "PYSUF=-amd64"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "PYSUF=-arm64"
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" if not defined PROCESSOR_ARCHITEW6432 set "PYSUF="
set "PYURL=https://www.python.org/ftp/python/3.12.10/python-3.12.10%PYSUF%.exe"
set "PYEXE=%TEMP%\gv-python-installer.exe"
echo Downloading %PYURL%
powershell -NoProfile -Command "$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -UseBasicParsing -Uri $env:PYURL -OutFile $env:PYEXE } catch { exit 1 }"
if errorlevel 1 (
    echo Download failed. Check your internet connection.
    exit /b 0
)
echo Installing Python ^(a progress window will appear, it takes 1-3 minutes^)...
start /wait "" "%PYEXE%" /passive InstallAllUsers=1 PrependPath=1 Include_launcher=1 Include_test=0 /log "%TEMP%\gv-python-install.log"
echo Python installer finished with code %errorlevel%.
del "%PYEXE%" >nul 2>&1
call :refreshpath
call :findpy
if not defined PY echo Python installer log: %TEMP%\gv-python-install.log
exit /b 0
