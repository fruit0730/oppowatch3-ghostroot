<#
  rootdev.ps1 -- talk to the rooted daemon that GhostLock-OWW212 leaves on the
  watch (127.0.0.1:25555, forwarded with `adb forward`).

  The daemon is a plain `sh -i` on a socket, so this client is request/response:
  each command is followed by `echo QEND_<id>_$?`, and we read until that marker
  comes back expanded (the terminal also echoes the command text itself, where
  `$?` is still literal, which is why the marker is only recognised once a digit
  follows it). One connection is kept open, so `cd` and shell variables persist.

  usage:
    powershell -File rootdev.ps1                      # interactive root shell
    powershell -File rootdev.ps1 -Cmd "id"            # one command, then exit
    powershell -File rootdev.ps1 -Cmd "getenforce" -TimeoutSec 30
#>
param(
    [string]$Cmd = "",
    [int]$Port = 25555,
    [int]$TimeoutSec = 600
)

$ErrorActionPreference = 'Stop'

function New-RootConn {
    $c = New-Object System.Net.Sockets.TcpClient
    $c.Connect('127.0.0.1', $Port)
    $s = $c.GetStream()
    $s.ReadTimeout = 1500
    return @{ client = $c; stream = $s }
}

function Invoke-RootCmd($conn, [string]$command, [int]$timeoutSec) {
    $st = $conn.stream
    $id = [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $marker = "QEND_${id}_"
    $re = New-Object Text.RegularExpressions.Regex ($marker + '\d+')
    $w = New-Object Text.UTF8Encoding($false)
    $bytes = $w.GetBytes($command + "`n" + "echo $marker`$?" + "`n")
    $st.Write($bytes, 0, $bytes.Length)
    $st.Flush()

    $buf = New-Object byte[] 65536
    $ms = New-Object IO.MemoryStream
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $timeoutSec) {
        try {
            $n = $st.Read($buf, 0, $buf.Length)
        } catch [System.IO.IOException] {
            continue                       # read timeout: keep waiting
        }
        if ($n -le 0) { break }
        $ms.Write($buf, 0, $n)
        $txt = $w.GetString($ms.ToArray())
        if ($re.IsMatch($txt)) {
            Start-Sleep -Milliseconds 150
            try {
                while (($n = $st.Read($buf, 0, $buf.Length)) -gt 0) { $ms.Write($buf, 0, $n) }
            } catch { }
            break
        }
    }
    $out = $w.GetString($ms.ToArray())
    # drop the first echo of what we typed, it is noise from the interactive shell
    $lines = $out -split "`r?`n"
    $keep = @()
    $skipped = $false
    foreach ($l in $lines) {
        if (-not $skipped -and $l -like "*$marker*") { $skipped = $true; continue }
        $keep += $l
    }
    return (($keep -join "`n") -replace "(?m)^QEND_\w+_\d+\s*$", "").Trim()
}

try {
    $conn = New-RootConn
} catch {
    Write-Host "cannot reach the rooted daemon on 127.0.0.1:$Port :"
    Write-Host "  run  root_auto.bat  first (it fires the exploit and does the adb forward)"
    exit 2
}

if ($Cmd) {
    Invoke-RootCmd $conn $Cmd $TimeoutSec
    exit 0
}

Write-Host "root shell on the OWW212 (single-line commands; Ctrl-C to leave, the daemon stays up)"
while ($true) {
    try { $line = Read-Host "OWW212# " } catch { break }
    if ($null -eq $line) { break }
    if ($line -match '^\s*(exit|quit)\s*$') { break }
    if ($line.Trim() -eq '') { continue }
    try {
        Invoke-RootCmd $conn $line $TimeoutSec
    } catch {
        Write-Host "connection lost: $($_.Exception.Message)"
        break
    }
}
