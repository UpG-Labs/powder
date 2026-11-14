[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string] $Recordings,

    [switch] $CaptureConnectUi,

    [switch] $Cleanup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$CaptureDirName = ".powder-capture-mitmproxy"
$StateFileName = ".powder-capture-state.json"
$ShutdownFileName = "shutdown.request"
$ReadyFileName = "recorder.ready"
$MitmproxyVersion = "12.3.1"
$DemuxHost = "dmx.upc.ubisoft.com"
$CaptureProcessNames = @(
    "Steep.exe",
    "steep.exe",
    "STEEP.EXE"
)
$ConnectUiProcessNames = @(
    "UplayWebCore.exe",
    "UbisoftConnectWebCore.exe"
)
$StoppedProcessNames = @(
    "Steep.exe",
    "upc.exe",
    "UbisoftConnect.exe",
    "UplayWebCore.exe",
    "UbisoftGameLauncher.exe",
    "UbisoftGameLauncher64.exe",
    "UbisoftConnectWebCore.exe",
    "UbisoftExtension.exe"
)
$RedirectHosts = @(
    "public-ubiservices.ubi.com",
    "msr-public-ubiservices.ubi.com",
    "public-im-ubiservices.ubi.com",
    "public-ws-ubiservices.ubi.com",
    "steep-prod-pc.steep.olympus.ubi.com",
    "dmx.upc.ubisoft.com",
    "channel-service.upc.ubi.com",
    "static3.cdn.ubi.com"
)

function Quote-ProcessArgument([string] $Value) {
    # Start-Process joins ArgumentList into a command line. Quote values that may contain spaces.
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Get-ProcessRecord([System.Diagnostics.Process] $Process) {
    $Process.Refresh()
    return [ordered]@{
        pid = $Process.Id
        start_time_utc = $Process.StartTime.ToUniversalTime().ToString("o")
    }
}

function Write-State([string] $Path, [System.Collections.IDictionary] $State) {
    $temporary = "$Path.tmp"
    $State | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Invoke-RecorderFinalizer([string] $UvPath, [string] $Repository, [string] $RecordingsRoot) {
    # Recovery should work even when capture.ps1 was invoked by an absolute
    # path from somewhere other than the repository root.
    Push-Location -LiteralPath $Repository
    try {
        & $UvPath run python -m tools.capture.recorder $RecordingsRoot | Out-Host
        return $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
}

function Stop-RecordedProcess($Record, [string] $Label, [int] $GraceMilliseconds = 3000) {
    if ($null -eq $Record -or $null -eq $Record.pid) {
        return $true
    }
    $processId = [int] $Record.pid
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return $true
    }
    try {
        $started = $process.StartTime.ToUniversalTime().ToString("o")
    }
    catch {
        Write-Warning "Could not verify the start time of $Label PID $($Record.pid); it was not stopped."
        return $false
    }
    if ($started -ne [string] $Record.start_time_utc) {
        Write-Warning "$Label PID $($Record.pid) has been reused by another process; it was not stopped."
        return $false
    }
    Write-Host "Stopping $Label (PID $($Record.pid))..."
    # Ctrl+C is delivered to processes sharing this console. Give mitmproxy time to run addon.done()
    # and atomically finalize its report before using the forced process-tree fallback.
    if ($process.WaitForExit($GraceMilliseconds)) {
        return $true
    }
    # uv/uvx wait on the actual Python process. /T stops that exact verified process tree as well.
    # Native stderr becomes a terminating PowerShell error under ErrorActionPreference=Stop. Preserve
    # finalization even if taskkill races an exiting child or cannot terminate an elevated descendant.
    $taskkillSucceeded = $true
    try {
        & taskkill.exe /PID $processId /T /F 2>$null | Out-Host
        $taskkillSucceeded = $LASTEXITCODE -eq 0
    }
    catch {
        $taskkillSucceeded = $false
        Write-Verbose "taskkill could not complete for $Label PID $processId; checking the process directly."
    }
    if (Get-Process -Id $processId -ErrorAction SilentlyContinue) {
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 250
    $rootStopped = $null -eq (Get-Process -Id $processId -ErrorAction SilentlyContinue)
    # A failed tree kill may have left an elevated descendant behind even when uvx itself exited.
    # Retain the CA/state and let a later -Cleanup verify the now-settled process tree.
    return $taskkillSucceeded -and $rootStopped
}

function Request-MitmdumpShutdown([string] $Path) {
    try {
        [IO.File]::WriteAllText($Path, "shutdown")
        return $true
    }
    catch {
        Write-Warning "Could not request a graceful mitmproxy shutdown; the process fallback will be used: $_"
        return $false
    }
}

function Get-CertificateThumbprint([string] $CertificatePath) {
    if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
        return $null
    }
    $certificate = Get-PfxCertificate -FilePath $CertificatePath
    return $certificate.Thumbprint.Replace(" ", "").ToUpperInvariant()
}

function Remove-CaptureCertificate([string] $Thumbprint) {
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
        return $true
    }
    $normalized = $Thumbprint.Replace(" ", "").ToUpperInvariant()
    if (-not (Test-Path -LiteralPath "Cert:\CurrentUser\Root\$normalized")) {
        return $true
    }
    Write-Host "Removing the capture CA $normalized from the current user's trusted roots..."
    & certutil.exe -user -delstore Root $normalized | Out-Host
    if ($LASTEXITCODE -ne 0 -or (Test-Path -LiteralPath "Cert:\CurrentUser\Root\$normalized")) {
        Write-Warning "The capture CA could not be removed. Run this script again with -Cleanup."
        return $false
    }
    return $true
}

function Remove-CaptureDirectory([string] $Directory, [string] $RecordingsRoot) {
    if (-not (Test-Path -LiteralPath $Directory)) {
        return
    }
    $fullDirectory = [IO.Path]::GetFullPath($Directory).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $fullRoot = [IO.Path]::GetFullPath($RecordingsRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $prefix = $fullRoot + [IO.Path]::DirectorySeparatorChar
    if (-not $fullDirectory.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $fullDirectory) -ne $CaptureDirName) {
        throw "Refusing to remove unexpected capture directory: $fullDirectory"
    }
    Write-Host "Deleting the isolated capture CA and private key directory..."
    Remove-Item -LiteralPath $fullDirectory -Recurse -Force
}

function Get-CanonicalRecoveryPath($Value) {
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value) -or
        -not [IO.Path]::IsPathRooted($Value)) {
        return $null
    }
    try {
        $separators = [char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
        return [IO.Path]::GetFullPath($Value).TrimEnd($separators)
    }
    catch {
        return $null
    }
}

function Invoke-RecoveryCleanup([string] $StatePath, [string] $ConfDir, [string] $RecordingsRoot) {
    # Recovery state is stored beside private recordings and can be edited independently of this
    # script. Bind it to the directory selected on this invocation before trusting a PID or thumbprint.
    if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
        Write-Warning "Capture recovery state is missing; no process, certificate, or file was changed."
        return $false
    }
    try {
        $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    }
    catch {
        Write-Warning "Capture recovery state is unreadable; no process, certificate, or file was changed: $_"
        return $false
    }

    $requiredStateProperties = @("format", "recordings", "confdir", "ca_thumbprint", "attach", "mitmproxy")
    foreach ($property in $requiredStateProperties) {
        if ($null -eq $state -or $null -eq $state.PSObject.Properties[$property]) {
            Write-Warning "Capture recovery state is missing '$property'; no process, certificate, or file was changed."
            return $false
        }
    }
    $validFormatType = $state.format -is [int] -or $state.format -is [long]
    if (-not $validFormatType -or [long] $state.format -ne 1) {
        Write-Warning "Capture recovery state format is not supported; no process, certificate, or file was changed."
        return $false
    }

    $selectedRecordings = Get-CanonicalRecoveryPath $RecordingsRoot
    $selectedConfDir = Get-CanonicalRecoveryPath $ConfDir
    $recordedRecordings = Get-CanonicalRecoveryPath $state.recordings
    $recordedConfDir = Get-CanonicalRecoveryPath $state.confdir
    if ($null -eq $selectedRecordings -or $null -eq $selectedConfDir -or
        $null -eq $recordedRecordings -or $null -eq $recordedConfDir -or
        -not $selectedRecordings.Equals($recordedRecordings, [StringComparison]::OrdinalIgnoreCase) -or
        -not $selectedConfDir.Equals($recordedConfDir, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Warning "Capture recovery state does not match the selected recordings directory; no process, certificate, or file was changed."
        return $false
    }

    $thumbprint = [string] $state.ca_thumbprint
    if ($thumbprint -notmatch "^[0-9A-Fa-f]{40}$") {
        Write-Warning "Capture recovery state has no valid CA thumbprint; no process, certificate, or file was changed."
        return $false
    }
    $caFile = Join-Path $ConfDir "mitmproxy-ca-cert.cer"
    try {
        $certificateThumbprint = Get-CertificateThumbprint $caFile
    }
    catch {
        Write-Warning "The isolated capture CA file is unreadable; no process, certificate, or file was changed: $_"
        return $false
    }
    if ($certificateThumbprint -notmatch "^[0-9A-F]{40}$" -or
        $thumbprint.ToUpperInvariant() -ne $certificateThumbprint) {
        Write-Warning "Capture recovery state does not match its isolated CA file; no process, certificate, or file was changed."
        return $false
    }

    $attachStopped = Stop-RecordedProcess $state.attach "Steep TLS-helper watcher"
    $null = Request-MitmdumpShutdown (Join-Path $ConfDir $ShutdownFileName)
    $mitmStopped = Stop-RecordedProcess $state.mitmproxy "mitmproxy" 15000
    if (-not $attachStopped -or -not $mitmStopped) {
        Write-Warning "A recorded capture process could not be stopped safely; CA/key state was retained."
        return $false
    }

    $certificateRemoved = Remove-CaptureCertificate $thumbprint
    if (-not $certificateRemoved) {
        return $false
    }
    Remove-CaptureDirectory $ConfDir $RecordingsRoot
    if (Test-Path -LiteralPath $StatePath) {
        Remove-Item -LiteralPath $StatePath -Force
    }
    return $true
}

function Assert-NoRedirectedHosts {
    $hostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
    if (-not (Test-Path -LiteralPath $hostsPath -PathType Leaf)) {
        return
    }
    $conflicts = New-Object System.Collections.Generic.List[string]
    foreach ($line in Get-Content -LiteralPath $hostsPath) {
        if ($line -match "Powder launcher redirect|steep-re launcher redirect|steep-re emulator redirect") {
            $conflicts.Add($line.Trim())
            continue
        }
        $withoutComment = ($line -split "#", 2)[0].Trim()
        if (-not $withoutComment) {
            continue
        }
        $parts = $withoutComment -split "\s+"
        if ($parts.Count -lt 2) {
            continue
        }
        foreach ($alias in $parts[1..($parts.Count - 1)]) {
            if ($RedirectHosts -contains $alias.ToLowerInvariant()) {
                $conflicts.Add($line.Trim())
                break
            }
        }
    }
    if ($conflicts.Count -gt 0) {
        $sample = ($conflicts | Select-Object -First 3) -join "; "
        throw "The Windows hosts file still redirects Ubisoft hosts ($sample). Run 'uv run powder --restore' first."
    }
}

function Assert-TargetProcessesStopped {
    $baseNames = $StoppedProcessNames | ForEach-Object { [IO.Path]::GetFileNameWithoutExtension($_) }
    $running = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $baseNames -contains $_.ProcessName } |
        Select-Object -ExpandProperty ProcessName -Unique
    if ($running) {
        throw "Close Steep and Ubisoft Connect before capture. Still running: $($running -join ', ')."
    }
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
if ([string]::IsNullOrWhiteSpace($Recordings)) {
    $Recordings = Join-Path $repoRoot "recordings"
}
elseif (-not [IO.Path]::IsPathRooted($Recordings)) {
    $Recordings = Join-Path (Get-Location).Path $Recordings
}
$recordingsRoot = [IO.Path]::GetFullPath($Recordings)
$pathRoot = [IO.Path]::GetPathRoot($recordingsRoot)
$pathSeparators = [char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
$trimmedRecordings = $recordingsRoot.TrimEnd($pathSeparators)
$trimmedRoot = $pathRoot.TrimEnd($pathSeparators)
if ($trimmedRecordings -eq $trimmedRoot) {
    throw "Refusing to use a filesystem root as the recordings directory."
}
$recordingsRoot = $trimmedRecordings
New-Item -ItemType Directory -Path $recordingsRoot -Force | Out-Null

$confDir = Join-Path $recordingsRoot $CaptureDirName
$statePath = Join-Path $recordingsRoot $StateFileName
$caCertificate = Join-Path $confDir "mitmproxy-ca-cert.cer"
$shutdownFile = Join-Path $confDir $ShutdownFileName
$readyFile = Join-Path $confDir $ReadyFileName

if ($Cleanup) {
    if (Invoke-RecoveryCleanup $statePath $confDir $recordingsRoot) {
        $cleanupUv = Get-Command uv -ErrorAction SilentlyContinue
        if ($null -ne $cleanupUv) {
            try {
                $finalizeExit = Invoke-RecorderFinalizer $cleanupUv.Source $repoRoot $recordingsRoot
                if ($finalizeExit -ne 0) {
                    Write-Warning "Cleanup succeeded, but the recording journal could not be finalized."
                }
            }
            catch {
                Write-Warning "Cleanup succeeded, but the recording journal could not be finalized: $_"
            }
        }
        else {
            Write-Warning "uv was not found; rerun the recorder later to finalize its crash journal."
        }
        Write-Host "Capture cleanup is complete. Recordings were left in $recordingsRoot"
        exit 0
    }
    exit 1
}

if ((Test-Path -LiteralPath $statePath) -or (Test-Path -LiteralPath $confDir)) {
    throw "A previous capture did not finish cleanup. Run this command with -Cleanup first."
}

$uv = Get-Command uv -ErrorAction SilentlyContinue
$uvx = Get-Command uvx -ErrorAction SilentlyContinue
if ($null -eq $uv -or $null -eq $uvx) {
    throw "uv and uvx are required. Install uv, then reopen this terminal."
}

$addonPath = Join-Path $PSScriptRoot "addon.py"
$attachPath = Join-Path $PSScriptRoot "attach_game.py"
$hookDll = Join-Path $repoRoot "native\bin\hook_guard.dll"
$armerExe = Join-Path $repoRoot "native\bin\armer.exe"
foreach ($required in @($addonPath, $attachPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Capture component is missing: $required"
    }
}
if (-not (Test-Path -LiteralPath $hookDll -PathType Leaf) -or
    -not (Test-Path -LiteralPath $armerExe -PathType Leaf)) {
    throw "The Steep TLS helper is not built. Run 'native\build.ps1' from the repository root first."
}

Assert-TargetProcessesStopped
Assert-NoRedirectedHosts

Write-Host ""
Write-Host "Powder capture will now start mitmproxy local capture." -ForegroundColor Cyan
Write-Host "Windows may show a UAC prompt for mitmproxy's packet redirector."
Write-Host "Afterward, Windows will ask you to trust a temporary capture CA for this user."
Write-Host "That CA is removed, and its private key deleted, when capture stops."
Write-Host "Do not start Ubisoft Connect until this script says the recorder is ready."
Write-Host ""

$state = [ordered]@{
    format = 1
    recordings = $recordingsRoot
    confdir = $confDir
    ca_thumbprint = $null
    mitmproxy = $null
    attach = $null
    started_utc = [DateTime]::UtcNow.ToString("o")
}
$mitmProcess = $null
$attachProcess = $null
$attachFinished = $false
$cleaned = $false

try {
    New-Item -ItemType Directory -Path $confDir -Force | Out-Null
    Write-State $statePath $state

    # Keep Connect's login/session processes outside the redirector entirely. The optional second
    # pass captures only Chromium UI processes for achievement/configuration assets.
    if ($CaptureConnectUi) {
        $CaptureProcessNames = @($ConnectUiProcessNames)
    }
    $mode = "local:" + ($CaptureProcessNames -join ",")
    # The official demux edge rejects mitmproxy's replacement upstream TLS connection. Preserve
    # the established passthrough without using a broad allow-list that would miss no-SNI game TLS.
    $demuxPassthroughPattern = "^" + [regex]::Escape($DemuxHost) + "(?::443)?$"
    $interceptionArguments = @(
        "--ignore-hosts", (Quote-ProcessArgument $demuxPassthroughPattern)
    )
    if ($CaptureConnectUi) {
        # Chromium supplies SNI, so host filtering can protect unrelated WebCore traffic. STEEP's
        # older TLS stack may not: the game-only pass must decrypt before its HTTP Host is visible.
        $CaptureHosts = @($RedirectHosts | Where-Object { $_ -ne $DemuxHost })
        $allowedHostsPattern = "^(?:" + (($CaptureHosts | ForEach-Object {
            [regex]::Escape($_)
        }) -join "|") + ")(?::\d+)?$"
        $interceptionArguments += @(
            "--allow-hosts", (Quote-ProcessArgument $allowedHostsPattern),
            # Chromium does not trust a user-installed capture CA for QUIC. Force its TCP fallback.
            "--set", "http3=false"
        )
    }
    $mitmArguments = @(
        "--from", "mitmproxy==$MitmproxyVersion",
        "mitmdump",
        "--mode", (Quote-ProcessArgument $mode)
    )
    $mitmArguments += $interceptionArguments
    $mitmArguments += @(
        "-s", (Quote-ProcessArgument $addonPath),
        "--set", (Quote-ProcessArgument "powder_recordings=$recordingsRoot"),
        "--set", (Quote-ProcessArgument "confdir=$confDir"),
        "--set", (Quote-ProcessArgument "powder_shutdown_file=$shutdownFile"),
        "--set", (Quote-ProcessArgument "powder_ready_file=$readyFile"),
        "--set", "flow_detail=0"
    )
    $mitmProcess = Start-Process -FilePath $uvx.Source -ArgumentList $mitmArguments -WorkingDirectory $repoRoot `
        -NoNewWindow -PassThru
    $state.mitmproxy = Get-ProcessRecord $mitmProcess
    Write-State $statePath $state

    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    while (-not (Test-Path -LiteralPath $caCertificate -PathType Leaf) -or
           -not (Test-Path -LiteralPath $readyFile -PathType Leaf)) {
        $mitmProcess.Refresh()
        if ($mitmProcess.HasExited) {
            $mitmProcess.WaitForExit()
            $mitmExitCode = $mitmProcess.ExitCode
            if ($null -eq $mitmExitCode) {
                throw "mitmproxy exited before its CA and recorder were ready, but Windows did not provide its exit code."
            }
            throw "mitmproxy exited before its CA and recorder were ready (exit code $mitmExitCode)."
        }
        if ([DateTime]::UtcNow -gt $deadline) {
            throw "Timed out waiting for mitmproxy's CA and recorder addon."
        }
        Start-Sleep -Milliseconds 250
    }

    # Both files are published asynchronously. Recheck the child after observing them so an
    # immediately failed startup cannot reach certificate trust or launch the attachment helper.
    $mitmProcess.Refresh()
    if ($mitmProcess.HasExited) {
        $mitmProcess.WaitForExit()
        $mitmExitCode = $mitmProcess.ExitCode
        if ($null -eq $mitmExitCode) {
            throw "mitmproxy exited after reporting readiness, but Windows did not provide its exit code."
        }
        throw "mitmproxy exited after reporting readiness (exit code $mitmExitCode)."
    }

    $thumbprint = Get-CertificateThumbprint $caCertificate
    if ([string]::IsNullOrWhiteSpace($thumbprint)) {
        throw "Could not read the capture CA certificate at $caCertificate"
    }
    $state.ca_thumbprint = $thumbprint
    Write-State $statePath $state

    Write-Host "Installing temporary capture CA $thumbprint for the current Windows user..."
    & certutil.exe -user -addstore Root $caCertificate | Out-Host
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath "Cert:\CurrentUser\Root\$thumbprint")) {
        throw "Windows did not install the temporary capture CA."
    }

    $attachArguments = @(
        "run", "python", (Quote-ProcessArgument $attachPath)
    )
    $attachProcess = Start-Process -FilePath $uv.Source -ArgumentList $attachArguments -WorkingDirectory $repoRoot `
        -NoNewWindow -PassThru
    $state.attach = Get-ProcessRecord $attachProcess
    Write-State $statePath $state

    Write-Host ""
    Write-Host "Recorder ready." -ForegroundColor Green
    Write-Host "Redirected processes: $($CaptureProcessNames -join ', ')"
    Write-Host "Start Ubisoft Connect normally, sign in to your legitimate account, and launch Steep."
    Write-Host "Follow the capture checklist in tools\capture\README.md."
    Write-Host "When finished, close Steep and press Ctrl+C in this window."
    Write-Host "Recordings: $recordingsRoot"
    Write-Host ""

    while ($true) {
        $mitmProcess.Refresh()
        if ($mitmProcess.HasExited) {
            # Start-Process -PassThru can leave ExitCode unset on Windows PowerShell until
            # WaitForExit() has populated the native process status.
            $mitmProcess.WaitForExit()
            $mitmExitCode = $mitmProcess.ExitCode
            if ($null -eq $mitmExitCode) {
                throw "mitmproxy exited, but Windows did not provide its exit code."
            }
            if ($mitmExitCode -ne 0) {
                throw "mitmproxy exited with code $mitmExitCode."
            }
            break
        }
        if (-not $attachFinished -and $null -ne $attachProcess) {
            $attachProcess.Refresh()
            if ($attachProcess.HasExited) {
                $attachProcess.WaitForExit()
                $attachExitCode = $attachProcess.ExitCode
                if ($null -eq $attachExitCode) {
                    throw "The Steep TLS-helper watcher exited, but Windows did not provide its exit code."
                }
                if ($attachExitCode -ne 0) {
                    throw "The Steep TLS-helper watcher exited with code $attachExitCode. Do not continue the game through the title screen."
                }
                $attachFinished = $true
                Write-Host "Steep closed; the network recorder is still running until you press Ctrl+C."
            }
        }
        Start-Sleep -Seconds 1
    }
}
finally {
    $childrenStopped = $true
    if ($null -ne $state.attach) {
        $childrenStopped = (Stop-RecordedProcess $state.attach "Steep TLS-helper watcher") -and $childrenStopped
    }
    if ($null -ne $state.mitmproxy) {
        $null = Request-MitmdumpShutdown $shutdownFile
        $childrenStopped = (Stop-RecordedProcess $state.mitmproxy "mitmproxy" 15000) -and $childrenStopped
    }

    if ($childrenStopped) {
        try {
            $finalizeExit = Invoke-RecorderFinalizer $uv.Source $repoRoot $recordingsRoot
            if ($finalizeExit -ne 0) {
                Write-Warning "The capture journal could not be finalized; rerunning capture will replay it."
            }
        }
        catch {
            # Certificate/key cleanup is more important than report generation.
            Write-Warning "The capture journal could not be finalized; rerunning capture will replay it: $_"
        }
    }
    else {
        Write-Warning "A capture process could not be stopped safely; CA/key state was retained for -Cleanup."
    }

    $thumbprint = if ($null -ne $state.ca_thumbprint) { [string] $state.ca_thumbprint } else { $null }
    $caFileThumbprint = Get-CertificateThumbprint $caCertificate
    $thumbprintMatches = ([string]::IsNullOrWhiteSpace($thumbprint) -or
                          [string]::IsNullOrWhiteSpace($caFileThumbprint) -or
                          $thumbprint.Replace(" ", "").ToUpperInvariant() -eq $caFileThumbprint)
    if (-not $thumbprintMatches) {
        Write-Warning "Capture state thumbprint does not match its isolated CA file; CA/key state was retained."
    }
    $certificateRemoved = $childrenStopped -and $thumbprintMatches -and (Remove-CaptureCertificate $thumbprint)
    if ($childrenStopped -and $certificateRemoved) {
        try {
            Remove-CaptureDirectory $confDir $recordingsRoot
            if (Test-Path -LiteralPath $statePath) {
                Remove-Item -LiteralPath $statePath -Force
            }
            $cleaned = $true
        }
        catch {
            Write-Warning "Could not delete the isolated capture key directory: $_"
        }
    }

    if ($cleaned) {
        Write-Host "Capture stopped; temporary CA and private key removed." -ForegroundColor Green
        Write-Host "Review $recordingsRoot\capture-report.json, then build the pack as described in the README."
    }
    else {
        Write-Warning "Cleanup is incomplete. Recordings are safe; rerun this script with -Cleanup."
    }
}
