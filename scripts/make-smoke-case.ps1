<#
.SYNOPSIS
    Generate the host-exported half of the VERDICT smoke case (Part B of
    checklist item 5). Run ONCE, elevated, on the Windows build host.

.DESCRIPTION
    The unelevated build session already committed the authored smoke
    artifacts (the 12-byte mimikatz.exe decoy, rules/smoke.yar, the YARA
    bait invoice, and the clean case). This script produces the four
    artifacts that require Administrator to create authentically:

        cases/smoke/Security.evtx      - real 4624 (type-3) + 4625 logons
        cases/smoke/System.evtx        - real 7045 service-install record
        cases/smoke/NTUSER.DAT         - real regf hive with a Run key
        cases/smoke/UPDATE.EXE-*.pf    - real prefetch for update.exe

    Everything is generated from synthetic activity this script performs on
    the local host, then exported with a tight time-window filter so no
    unrelated log data is carried along. The only durable outputs are the
    files written into cases/smoke/. Every host object this script creates
    is named VerdictSmoke* and is deleted again before exit.

    SAFETY: this script never touches, stops, disables, or reconfigures any
    existing service, account, audit policy, or setting. It never disables
    Defender, never whitelists anything, and never reboots. It is idempotent
    (re-runnable) and cleans up after itself even on partial failure.

.NOTES
    PowerShell 5.1 compatible. Run as Administrator:
        Right-click -> "Run as administrator", or
        Start-Process powershell -Verb RunAs -ArgumentList '-NoExit','-ExecutionPolicy','Bypass','-File','<path>\make-smoke-case.ps1'
#>

# ----------------------------------------------------------------- helpers

$script:Failures = New-Object System.Collections.Generic.List[string]

function Write-Banner($msg) { Write-Host ""; Write-Host "==== $msg ====" -ForegroundColor Cyan }
function Write-Step($msg)   { Write-Host ""; Write-Host "[STEP] $msg" -ForegroundColor White }
function Write-Do($msg)     { Write-Host "   -> $msg" -ForegroundColor Gray }
function Write-Pass($msg)   { Write-Host "   PASS  $msg" -ForegroundColor Green }
function Write-Fail($msg)   { Write-Host "   FAIL  $msg" -ForegroundColor Red; $script:Failures.Add($msg) }

# ------------------------------------------------------------- elevation

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host ""
    Write-Host "ERROR: this script must run elevated (as Administrator)." -ForegroundColor Red
    Write-Host "  Prefetch, the Security event log, sc.exe create, and reg.exe save" -ForegroundColor Red
    Write-Host "  all require admin. Right-click the script and choose" -ForegroundColor Red
    Write-Host "  'Run as administrator', then re-run." -ForegroundColor Red
    exit 1
}

# ------------------------------------------------------------- constants

$RepoRoot     = Split-Path -Parent $PSScriptRoot
$SmokeDir     = Join-Path $RepoRoot 'cases\smoke'
$PrefetchDir  = Join-Path $env:SystemRoot 'Prefetch'
$SourceExe    = Join-Path $env:SystemRoot 'System32\where.exe'
$PublicExe    = 'C:\Users\Public\update.exe'
$UserName     = 'VerdictSmoke'
$SvcName      = 'VerdictSmokeSvc'
$HiveKeyReg   = 'HKCU\VerdictSmokeHive'                  # for reg.exe
$HiveKeyPS    = 'HKCU:\VerdictSmokeHive'                 # for PowerShell
$RunKeyPS     = 'HKCU:\VerdictSmokeHive\Software\Microsoft\Windows\CurrentVersion\Run'
$VerifyMount  = 'HKLM\VERDICT_SMOKE_VERIFY'              # scratch reg load
$VerifyRunKey = 'HKLM\VERDICT_SMOKE_VERIFY\Software\Microsoft\Windows\CurrentVersion\Run'
$SecOut       = Join-Path $SmokeDir 'Security.evtx'
$SysOut       = Join-Path $SmokeDir 'System.evtx'
$HiveOut      = Join-Path $SmokeDir 'NTUSER.DAT'
$Share        = '\\127.0.0.1\IPC$'

if (-not (Test-Path $SmokeDir)) { New-Item -ItemType Directory -Path $SmokeDir -Force | Out-Null }

# Marker timestamp (UTC): every event export is filtered to "at/after now"
# so only the activity this run generates is exported.
$T0    = (Get-Date).ToUniversalTime()
$T0Iso = $T0.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

Write-Banner "VERDICT smoke-case host export"
Write-Host "Repo root : $RepoRoot"
Write-Host "Smoke dir : $SmokeDir"
Write-Host "T0 (UTC)  : $T0Iso   (event exports filtered to >= this)"

# --------------------------------------------------------- cleanup routine

function Invoke-Cleanup {
    param([string]$Phase)
    Write-Step "CLEANUP ($Phase): removing all VerdictSmoke* host objects"

    # Scratch verify mount (may be left loaded by a crashed prior run).
    & reg.exe query $VerifyMount > $null 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Do "reg unload $VerifyMount"
        & reg.exe unload $VerifyMount > $null 2>&1
    }

    # Scratch HKCU hive key.
    if (Test-Path $HiveKeyPS) {
        Write-Do "remove $HiveKeyPS"
        try { Remove-Item -Path $HiveKeyPS -Recurse -Force -ErrorAction Stop } catch { Write-Do "  (ignored: $($_.Exception.Message))" }
    }

    # Scratch service.
    & sc.exe query $SvcName > $null 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Do "sc.exe delete $SvcName"
        & sc.exe delete $SvcName > $null 2>&1
    }

    # Scratch local user.
    & net.exe user $UserName > $null 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Do "net user $UserName /delete"
        & net.exe user $UserName /delete > $null 2>&1
    }

    # Any lingering loopback IPC$ connection.
    & net.exe use $Share /delete /y > $null 2>&1

    # The planted benign exe.
    if (Test-Path $PublicExe) {
        Write-Do "remove $PublicExe"
        try { Remove-Item -Path $PublicExe -Force -ErrorAction Stop } catch { Write-Do "  (ignored: $($_.Exception.Message))" }
    }

    Write-Host "   cleanup ($Phase) complete." -ForegroundColor DarkGray
}

# Pre-clean: tolerate leftovers from a failed prior run before we start.
Invoke-Cleanup -Phase "pre-run"

try {
    # ----------------------------------------------------- STEP 1: prefetch
    Write-Step "1. Create + execute C:\Users\Public\update.exe to generate prefetch"
    Write-Do "copy `"$SourceExe`" -> `"$PublicExe`" (benign signed Windows binary)"
    Copy-Item -Path $SourceExe -Destination $PublicExe -Force

    $sysmain = Get-Service -Name SysMain -ErrorAction SilentlyContinue
    if ($null -eq $sysmain) {
        Write-Fail "SysMain service not found - prefetch cannot be generated on this host"
    } elseif ($sysmain.Status -ne 'Running') {
        Write-Fail "SysMain is '$($sysmain.Status)', not Running - prefetch will not be written (NOT starting it: we never reconfigure services)"
    } else {
        Write-Do "SysMain confirmed Running"
    }

    Write-Do "execute update.exe once (Start-Process ... -Wait)"
    try {
        Start-Process -FilePath $PublicExe -ArgumentList 'where.exe' -NoNewWindow -Wait -ErrorAction Stop
    } catch {
        Write-Do "  (execution returned: $($_.Exception.Message))"
    }

    Write-Do "poll $PrefetchDir for UPDATE.EXE-*.pf (up to 60s)"
    $pf = $null
    for ($i = 0; $i -lt 60; $i++) {
        $pf = Get-ChildItem -Path $PrefetchDir -Filter 'UPDATE.EXE-*.pf' -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($null -ne $pf) { break }
        Start-Sleep -Seconds 1
    }
    if ($null -ne $pf) {
        $pfDest = Join-Path $SmokeDir $pf.Name
        Copy-Item -Path $pf.FullName -Destination $pfDest -Force
        Write-Pass "prefetch captured: $($pf.Name) ($([int]($pf.Length/1KB)) KB) -> cases/smoke/"
    } else {
        Write-Fail "no UPDATE.EXE-*.pf appeared within 60s (prefetch may be disabled on this host)"
    }

    # --------------------------------------------- STEP 2: type-3 logons
    Write-Step "2. Generate type-3 (network) logons via a throwaway local user"
    # <= 14 chars: longer passwords make net.exe block on an interactive
    # "longer than 14 characters, continue? (Y/N)" prompt.
    $Password = 'V#' + ([System.Guid]::NewGuid().ToString('N').Substring(0,8)) + '9q!'
    Write-Do "net user $UserName <random-password> /add  (no admin groups)"
    & net.exe user $UserName $Password /add > $null 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "could not create local user $UserName (password policy?)"
    } else {
        Write-Do "successful network logon: net use $Share /user:$UserName (-> 4624 type 3)"
        & net.exe use $Share /user:$UserName $Password > $null 2>&1
        if ($LASTEXITCODE -eq 0) {
            & net.exe use $Share /delete /y > $null 2>&1
        } else {
            Write-Do "  (loopback IPC$ connect returned exit $LASTEXITCODE)"
        }
        Write-Do "failed logon for texture: net use $Share with a wrong password (-> 4625)"
        & net.exe use $Share /user:$UserName 'WrongPa$$w0rd-Nope!' > $null 2>&1
        & net.exe use $Share /delete /y > $null 2>&1
        Write-Do "net user $UserName /delete"
        & net.exe user $UserName /delete > $null 2>&1
        Write-Pass "logon activity generated and user removed"
    }

    # ------------------------------------------- STEP 3: 7045 service install
    Write-Step "3. Generate Event ID 7045 (service install) - NEVER started"
    Write-Do "sc.exe create $SvcName binPath= `"$PublicExe`" start= demand"
    & sc.exe create $SvcName binPath= "$PublicExe" start= demand > $null 2>&1
    $scCreate = $LASTEXITCODE
    if ($scCreate -eq 0) {
        Write-Do "sc.exe delete $SvcName  (the 7045 is already logged)"
        & sc.exe delete $SvcName > $null 2>&1
        Write-Pass "service install event generated and service removed"
    } else {
        Write-Fail "sc.exe create returned exit $scCreate - no 7045 generated"
    }

    # ---------------------------------------------- STEP 4: export filtered logs
    Write-Step "4. Export time-window-filtered event logs (never the whole log)"
    # Event-log writes commit asynchronously: the 7045 from step 3 can land in
    # the log a moment AFTER sc.exe returns. Without this pause the export
    # races the flush and captures nothing (observed in the first full run).
    Write-Do "waiting 3s for event-log flush (7045 commit races sc.exe exit)"
    Start-Sleep -Seconds 3
    $secQuery = "*[System[(EventID=4624 or EventID=4625) and TimeCreated[@SystemTime>='$T0Iso']]]"
    $sysQuery = "*[System[(EventID=7045) and TimeCreated[@SystemTime>='$T0Iso']]]"

    Write-Do "wevtutil epl Security -> cases/smoke/Security.evtx  (4624/4625 since T0)"
    & wevtutil.exe epl Security "$SecOut" "/q:$secQuery" "/ow:true"
    if ($LASTEXITCODE -eq 0 -and (Test-Path $SecOut)) {
        Write-Pass "Security.evtx exported"
    } else {
        Write-Fail "wevtutil export of Security failed (exit $LASTEXITCODE)"
    }

    Write-Do "wevtutil epl System -> cases/smoke/System.evtx  (7045 since T0)"
    & wevtutil.exe epl System "$SysOut" "/q:$sysQuery" "/ow:true"
    if ($LASTEXITCODE -eq 0 -and (Test-Path $SysOut)) {
        Write-Pass "System.evtx exported"
    } else {
        Write-Fail "wevtutil export of System failed (exit $LASTEXITCODE)"
    }

    # ------------------------------------------------- STEP 5: build the hive
    Write-Step "5. Build a real NTUSER.DAT hive with a persistence Run key"
    Write-Do "create scratch key $RunKeyPS"
    New-Item -Path $RunKeyPS -Force | Out-Null
    Write-Do "set Updater = $PublicExe (REG_SZ)"
    New-ItemProperty -Path $RunKeyPS -Name 'Updater' -Value $PublicExe -PropertyType String -Force | Out-Null
    Write-Do "reg.exe save $HiveKeyReg -> cases/smoke/NTUSER.DAT"
    & reg.exe save $HiveKeyReg "$HiveOut" /y > $null 2>&1
    $saveRc = $LASTEXITCODE
    Write-Do "remove scratch key $HiveKeyPS"
    try { Remove-Item -Path $HiveKeyPS -Recurse -Force -ErrorAction Stop } catch { Write-Do "  (ignored: $($_.Exception.Message))" }
    if ($saveRc -eq 0 -and (Test-Path $HiveOut)) {
        Write-Pass "NTUSER.DAT hive saved"
    } else {
        Write-Fail "reg.exe save failed (exit $saveRc)"
    }

    # --------------------------------------------------- STEP 6: self-verify
    Write-Step "6. Self-verify the produced artifacts"

    # 6a. Security: >=1 4624 with LogonType 3
    if (Test-Path $SecOut) {
        $secEvents = @()
        try { $secEvents = @(Get-WinEvent -Path $SecOut -ErrorAction Stop) } catch { $secEvents = @() }
        $type3 = 0
        foreach ($e in $secEvents) {
            if ($e.Id -ne 4624) { continue }
            $x = [xml]$e.ToXml()
            foreach ($d in $x.Event.EventData.Data) {
                if ($d.Name -eq 'LogonType' -and "$($d.'#text')" -eq '3') { $type3++ }
            }
        }
        $c4625 = @($secEvents | Where-Object { $_.Id -eq 4625 }).Count
        if ($type3 -ge 1) {
            Write-Pass "Security.evtx: $type3 x 4624 type-3 logon(s), $c4625 x 4625 (total $($secEvents.Count) events)"
        } else {
            Write-Fail "Security.evtx: no 4624 LogonType=3 found (audit policy for Logon may be off; $($secEvents.Count) events present)"
        }
    } else {
        Write-Fail "Security.evtx missing - cannot verify logons"
    }

    # 6b. System: 7045 with the right ImagePath
    if (Test-Path $SysOut) {
        $sysEvents = @()
        try { $sysEvents = @(Get-WinEvent -Path $SysOut -ErrorAction Stop) } catch { $sysEvents = @() }
        $svc7045 = @($sysEvents | Where-Object { $_.Id -eq 7045 })
        $imgOk = $false
        if ($svc7045.Count -ge 1) {
            $x = [xml]$svc7045[0].ToXml()
            foreach ($d in $x.Event.EventData.Data) {
                if ($d.Name -eq 'ImagePath' -and "$($d.'#text')" -eq $PublicExe) { $imgOk = $true }
            }
        }
        if ($imgOk) {
            Write-Pass "System.evtx: 7045 with ImagePath = $PublicExe"
        } else {
            Write-Fail "System.evtx: no 7045 with ImagePath=$PublicExe ($($svc7045.Count) x 7045 present)"
        }
    } else {
        Write-Fail "System.evtx missing - cannot verify service install"
    }

    # 6c. Prefetch: exists, >1KB, MAM magic
    $pfFile = Get-ChildItem -Path $SmokeDir -Filter 'UPDATE.EXE-*.pf' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $pfFile) {
        $magic = [System.IO.File]::ReadAllBytes($pfFile.FullName)[0..2]
        $isMam = ($magic.Count -ge 3 -and $magic[0] -eq 0x4D -and $magic[1] -eq 0x41 -and $magic[2] -eq 0x4D)
        if ($pfFile.Length -gt 1024 -and $isMam) {
            Write-Pass "$($pfFile.Name): $([int]($pfFile.Length/1KB)) KB, starts with MAM magic"
        } else {
            Write-Fail "$($pfFile.Name): size=$($pfFile.Length) magic=$(($magic | ForEach-Object { '{0:X2}' -f $_ }) -join ' ') (expected >1KB + 4D 41 4D)"
        }
    } else {
        Write-Fail "no UPDATE.EXE-*.pf in cases/smoke - cannot verify prefetch"
    }

    # 6d. Hive: load -> query Run\Updater -> unload
    if (Test-Path $HiveOut) {
        & reg.exe load $VerifyMount "$HiveOut" > $null 2>&1
        if ($LASTEXITCODE -eq 0) {
            $q = & reg.exe query $VerifyRunKey /v Updater 2>&1
            & reg.exe unload $VerifyMount > $null 2>&1
            if (($q -join "`n") -match 'update\.exe') {
                Write-Pass "NTUSER.DAT: Run\Updater -> ...update.exe (loaded, queried, unloaded)"
            } else {
                Write-Fail "NTUSER.DAT: Run\Updater value not found on reload"
            }
        } else {
            Write-Fail "could not reg load NTUSER.DAT for verification (exit $LASTEXITCODE)"
        }
    } else {
        Write-Fail "NTUSER.DAT missing - cannot verify hive"
    }

    # 6e. Total size budget < 5 MB
    $produced = Get-ChildItem -Path $SmokeDir -File | Where-Object {
        $_.Name -in @('Security.evtx','System.evtx','NTUSER.DAT') -or $_.Name -like 'UPDATE.EXE-*.pf'
    }
    $allFiles = Get-ChildItem -Path $SmokeDir -File
    $totalBytes = ($allFiles | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $totalBytes) { $totalBytes = 0 }
    if ($totalBytes -lt 5MB) {
        Write-Pass "cases/smoke total size = $([int]($totalBytes/1KB)) KB (< 5 MB budget)"
    } else {
        Write-Fail "cases/smoke total size = $([int]($totalBytes/1KB)) KB exceeds the 5 MB budget"
    }
}
finally {
    # Always clean up host state, even on partial failure.
    Invoke-Cleanup -Phase "final"
}

# ----------------------------------------------------------------- summary
Write-Banner "Produced files in cases/smoke/"
Get-ChildItem -Path $SmokeDir -File | Sort-Object Name |
    Format-Table -AutoSize @{N='Name';E={$_.Name}}, @{N='Bytes';E={$_.Length}}, @{N='Modified';E={$_.LastWriteTime}}

if ($script:Failures.Count -eq 0) {
    Write-Host ""
    Write-Host "ALL CHECKS PASSED." -ForegroundColor Green
    Write-Host "NEXT: tell the build session the script finished - it will commit" -ForegroundColor Green
    Write-Host "      Security.evtx, System.evtx, NTUSER.DAT and the UPDATE.EXE-*.pf." -ForegroundColor Green
    exit 0
} else {
    Write-Host ""
    Write-Host "COMPLETED WITH $($script:Failures.Count) FAILURE(S):" -ForegroundColor Yellow
    foreach ($f in $script:Failures) { Write-Host "  - $f" -ForegroundColor Yellow }
    Write-Host "Re-run the script as administrator after addressing the above," -ForegroundColor Yellow
    Write-Host "or tell the build session which artifacts are present." -ForegroundColor Yellow
    exit 1
}
