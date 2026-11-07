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

if not exist "src\gv_proxy.py" (
    echo src\gv_proxy.py not found. Keep the folder structure of the archive.
    pause
    exit /b 1
)

call :getwd
if errorlevel 1 (
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
echo  1 - Install service
echo  2 - Remove service
echo  3 - Diagnostics
echo  4 - Exit
echo.
choice /c 1234 /n /m "Choice: "
if errorlevel 4 exit /b 0
if errorlevel 3 goto check
if errorlevel 2 goto uninstall_all
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
%PY% src\gv_proxy.py install
echo.
pause
goto menu

:check
cls
%PY% src\gv_proxy.py check
echo.
pause
goto menu

:uninstall_all
cls
%PY% src\gv_proxy.py uninstall
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

:getwd
rem WinDivert 2.2.2 (x64): the same version that zapret/winws uses. Downloaded only if the files are missing.
if exist "bin\WinDivert.dll" if exist "bin\WinDivert64.sys" exit /b 0
if not exist "bin" mkdir "bin"
echo WinDivert files not found in the bin folder. Downloading WinDivert 2.2.2 from github.com ...
set "WDZIP=%TEMP%\WinDivert-2.2.2-A.zip"
set "WDDIR=%TEMP%\gv-windivert"
powershell -NoProfile -Command "$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip' -OutFile $env:WDZIP } catch { exit 1 }; if ((Get-FileHash $env:WDZIP -Algorithm SHA256).Hash -ne '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15') { exit 2 }; if (Test-Path $env:WDDIR) { Remove-Item -Recurse -Force $env:WDDIR }; Expand-Archive -Path $env:WDZIP -DestinationPath $env:WDDIR -Force"
if errorlevel 2 (
    echo The downloaded archive does not match the expected SHA-256. Not using it.
    exit /b 1
)
if errorlevel 1 (
    echo Download failed. Copy WinDivert.dll and WinDivert64.sys ^(x64 folder of WinDivert 2.2.2^) into the bin folder.
    exit /b 1
)
copy /y "%WDDIR%\WinDivert-2.2.2-A\x64\WinDivert.dll" "%~dp0bin\WinDivert.dll" >nul
copy /y "%WDDIR%\WinDivert-2.2.2-A\x64\WinDivert64.sys" "%~dp0bin\WinDivert64.sys" >nul
del "%WDZIP%" >nul 2>&1
rd /s /q "%WDDIR%" >nul 2>&1
if not exist "bin\WinDivert.dll" exit /b 1
exit /b 0
