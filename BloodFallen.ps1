# ============================================================================================
# KinjiBloodFallen Forensic Triage Toolkit
# BloodFallen Basic Malware Check - Version 5.0 Community Preview
# coded with AI | Defensive Inspection Tool
#
# SAFETY:
# - This tool is inspection/evidence collection only.
# - It does NOT delete files, kill processes, disable services, remove tasks,
#   modify registry keys, read browser cookies, read passwords, or steal data.
# - Detection levels are heuristic-based and are NOT proof of malware.
# ============================================================================================
#
# Copyright (C) 2026  KinjiBloodFallen
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# If you fork, modify, or build on this project, please keep this notice
# and credit the original BloodFallen Forensic Triage Toolkit as your base.
# ============================================================================================

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# ============================================================================================
# CONFIGURATION
# ============================================================================================

# Leave blank by default.
# VirusTotal checking is MANUAL through Menu Option 16.
# Only SHA256 hashes are sent, never the actual file.
#
# You can set your key two ways:
# You can set your key two ways:
#   1. Paste it directly on the line below, OR
#   2. Leave it blank and choose Menu Option 16 (Manual file hash lookup),
#      which will offer to set/remove your key before running the check.
#      Once saved it's reloaded automatically the next time you run this script.
$VirusTotalApiKey = ""

# Number of days used by Recent Suspicious Files Scan.
$RecentFileDays = 14

# Maximum files checked per folder during recent-file scan.
$RecentFileLimitPerFolder = 250

#
Set-StrictMode -Version Latest

# ============================================================================================
# PATHS / GLOBAL VARIABLES
# ============================================================================================

if ($PSScriptRoot) {
    $BaseDir = Join-Path $PSScriptRoot "BloodFallen_Logs"
}
else {
    $BaseDir = Join-Path $PWD "BloodFallen_Logs"
}

$CacheFile = Join-Path $BaseDir "VirusTotal_Cache.json"
$ApiKeyFile = Join-Path $BaseDir "vt_config.json"

New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null

# If no key was hardcoded above, try loading one saved via Menu Option 16.
if (-not $VirusTotalApiKey -and (Test-Path -LiteralPath $ApiKeyFile)) {
    try {
        $savedKey = (Get-Content -LiteralPath $ApiKeyFile -Raw | ConvertFrom-Json).ApiKey

        if ($savedKey) {
            $VirusTotalApiKey = $savedKey
        }
    }
    catch {
        # Ignore a corrupt/unreadable config file; key simply stays blank.
    }
}

$SuspiciousCommandPattern = @(
    "powershell",
    "pwsh",
    "EncodedCommand",
    "-enc",
    "ExecutionPolicy",
    "Bypass",
    "Hidden",
    "WindowStyle",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "bitsadmin",
    "certutil",
    "invoke-webrequest",
    "invoke-expression",
    "iex\s*\(",
    "downloadstring",
    "frombase64string"
) -join "|"

$ScriptExtensionPattern = "\.(ps1|bat|cmd|vbs|js|jse|wsf|hta|scr)$"

$SuspiciousExtensionPattern = "\.(exe|dll|ps1|bat|cmd|vbs|js|jse|wsf|hta|scr|msi|lnk)$"

$SuspiciousPathPattern = @(
    "\\AppData\\Local\\Temp\\",
    "\\Windows\\Temp\\",
    "\\Temp\\",
    "\\Downloads\\",
    "\\Public\\",
    "\\ProgramData\\"
) -join "|"

# ============================================================================================
# HEADER / UI
# ============================================================================================

function Write-Header {
    Clear-Host

    Write-Host "============================================================================================" -ForegroundColor Red
    Write-Host "__________.____    ________   ________  ________  ___________      .__  .__       " -ForegroundColor Red
    Write-Host "\______   \    |   \_____  \  \_____  \ \______ \ \_   _____/____  |  | |  |   ____   ____" -ForegroundColor Red
    Write-Host " |    |  _/    |    /   |   \  /   |   \ |    |  \ |    __) \__  \ |  | |  | _/ __ \ /    \" -ForegroundColor Red
    Write-Host " |    |   \    |___/    |    \/    |    \|    `   \|     \   / __ \|  |_|  |_\  ___/|   |  \" -ForegroundColor Red
    Write-Host " |______  /_______ \_______  /\_______  /_______  /\___  /  (____  /____/____/\___  >___|  /" -ForegroundColor Red
    Write-Host "        \/        \/       \/         \/        \/     \/        \/               \/     \/ " -ForegroundColor Red
    Write-Host ""
    Write-Host "                 KinjiBloodFallen Forensic Triage Toolkit" -ForegroundColor Yellow
    Write-Host "                 Basic Malware Check - Version 5.0 Community Preview" -ForegroundColor Yellow
    Write-Host "                 coded with AI | Defensive Inspection Tool" -ForegroundColor DarkGray
    Write-Host "============================================================================================" -ForegroundColor Red
    Write-Host "Logs Folder: $BaseDir" -ForegroundColor Cyan
    Write-Host ""
	
	Show-Philosophy


}

function Show-Philosophy {

    Write-Host ""
    Write-Host " Inspection Philosophy" -ForegroundColor Cyan
    Write-Host " --------------------------------------------------------------------" -ForegroundColor DarkGray

    Write-Host "  [/] Read-Only Inspection" -ForegroundColor Green
    Write-Host "  [/] No Registry Modifications" -ForegroundColor Green
    Write-Host "  [/] No File Deletions" -ForegroundColor Green
    Write-Host "  [/] No Automatic Cleanup" -ForegroundColor Green
    Write-Host "  [/] Evidence Collection Only" -ForegroundColor Green
    Write-Host "  [/] User Makes The Final Decision" -ForegroundColor Green

    Write-Host ""
}

function Pause-Menu {
    Read-Host "`nPress Enter to return to the menu" | Out-Null
}

function Write-Status {
    param(
        [string]$Level,
        [string]$Message
    )

    switch ($Level) {
        "[HIGH]"   { Write-Host "$Level $Message" -ForegroundColor Red }
        "[MEDIUM]" { Write-Host "$Level $Message" -ForegroundColor Yellow }
        "[LOW]"    { Write-Host "$Level $Message" -ForegroundColor DarkYellow }
        "[INFO]"   { Write-Host "$Level $Message" -ForegroundColor Cyan }
        "[OK]"     { Write-Host "$Level $Message" -ForegroundColor Green }
        default    { Write-Host "$Level $Message" }
    }
}

function Test-IsAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)

        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Restart-AsAdministrator {
    if (Test-IsAdmin) {
        Write-Status "[OK]" "This script is already running as Administrator."
        return
    }

    try {
        $scriptPath = $PSCommandPath

        if (-not $scriptPath) {
            $scriptPath = $MyInvocation.MyCommand.Path
        }

        if (-not $scriptPath) {
            Write-Status "[MEDIUM]" "Could not determine the script path. Save the script as a .ps1 file first."
            return
        }

        Write-Host ""
        Write-Host "Requesting Administrator permission through Windows UAC..." -ForegroundColor Yellow

        Start-Process powershell.exe `
            -Verb RunAs `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

        Write-Host "A new elevated BloodFallen window should open." -ForegroundColor Green
        Write-Host "Closing this non-admin window..." -ForegroundColor DarkGray

        Start-Sleep -Seconds 2
        exit
    }
    catch {
        Write-Status "[MEDIUM]" "Administrator restart was cancelled or failed."
        Write-Host $_.Exception.Message -ForegroundColor DarkGray
    }
}

function New-RunLog {
    param(
        [string]$Name
    )

    $stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $folder = Join-Path $BaseDir "$stamp`_$Name"

    New-Item -ItemType Directory -Path $folder -Force | Out-Null

    return $folder
}

function Write-LogHeader {
    param(
        [string]$FilePath,
        [string]$Title
    )

    @(
        "============================================================================================"
        "KinjiBloodFallen Forensic Triage Toolkit - $Title"
        "Generated: $(Get-Date)"
        "Computer: $env:COMPUTERNAME"
        "User: $env:USERNAME"
        "Administrator: $(Test-IsAdmin)"
        "PowerShell Version: $($PSVersionTable.PSVersion)"
        "============================================================================================"
        ""
    ) | Out-File -FilePath $FilePath -Encoding UTF8
}

# ============================================================================================
# SYSTEM / FILE / TRUST FUNCTIONS
# ============================================================================================

function Test-InternetConnection {
    try {
        return (Test-NetConnection -ComputerName "www.virustotal.com" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue)
    }
    catch {
        return $false
    }
}

function Expand-EnvironmentPath {
    param(
        [string]$Path
    )

    if (-not $Path) {
        return $null
    }

    return [Environment]::ExpandEnvironmentVariables($Path)
}

function Get-ExecutablePathFromCommand {
    param(
        [string]$Execute,
        [string]$Arguments
    )

    $expandedExecute = Expand-EnvironmentPath $Execute
    $expandedArguments = Expand-EnvironmentPath $Arguments

    if (-not $expandedExecute) {
        $expandedExecute = ""
    }

    if (-not $expandedArguments) {
        $expandedArguments = ""
    }

    $combined = "$expandedExecute $expandedArguments".Trim()

    # ------------------------------------------------------------------------
    # 1. Extract a quoted executable/script path only.
    # Example:
    # "C:\Program Files\Discord\Update.exe" --processStart Discord.exe
    # ------------------------------------------------------------------------
    if ($combined -match '"([^"]+\.(exe|dll|ps1|bat|cmd|vbs|js|jse|wsf|hta|scr|msi))"') {
        $candidate = $matches[1]

        if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction SilentlyContinue) {
            return $candidate
        }
    }

    # ------------------------------------------------------------------------
    # 2. Only test Execute directly if it is a clean path with NO arguments.
    # ------------------------------------------------------------------------
    if ($expandedExecute) {
        $candidate = $expandedExecute.Trim()

        if ($candidate -match '^"(.+)"$') {
            $candidate = $matches[1]
        }

        if ($candidate -match '^[A-Za-z]:\\.+\.(exe|dll|ps1|bat|cmd|vbs|js|jse|wsf|hta|scr|msi)$') {
            if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction SilentlyContinue) {
                return $candidate
            }
        }
    }

    # ------------------------------------------------------------------------
    # 3. Extract an unquoted path only up to the file extension.
    # Example:
    # C:\Tools\App.exe -silent
    # ------------------------------------------------------------------------
    if ($combined -match '([A-Za-z]:\\.+?\.(exe|dll|ps1|bat|cmd|vbs|js|jse|wsf|hta|scr|msi))(?=\s|$)') {
        $candidate = $matches[1]

        if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction SilentlyContinue) {
            return $candidate
        }
    }

    # ------------------------------------------------------------------------
    # 4. Resolve common Windows command names safely.
    # ------------------------------------------------------------------------
    $systemCommands = @{
        "powershell.exe" = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
        "pwsh.exe"       = "$env:ProgramFiles\PowerShell\7\pwsh.exe"
        "cmd.exe"        = "$env:WINDIR\System32\cmd.exe"
        "wscript.exe"    = "$env:WINDIR\System32\wscript.exe"
        "cscript.exe"    = "$env:WINDIR\System32\cscript.exe"
        "rundll32.exe"   = "$env:WINDIR\System32\rundll32.exe"
        "regsvr32.exe"   = "$env:WINDIR\System32\regsvr32.exe"
        "mshta.exe"      = "$env:WINDIR\System32\mshta.exe"
        "svchost.exe"    = "$env:WINDIR\System32\svchost.exe"
    }

    foreach ($command in $systemCommands.Keys) {
        if ($combined -match [regex]::Escape($command)) {
            $candidate = $systemCommands[$command]

            if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction SilentlyContinue) {
                return $candidate
            }
        }
    }

    return $null
}

function Get-FileTrustInfo {
    param(
        [string]$FilePath
    )

    if (-not $FilePath) {
        return [PSCustomObject]@{
            FilePath        = $null
            FileResolved    = "No"
            FileExists      = "Unknown"
            SignatureStatus = "Not Checked"
            Publisher       = "Not Checked"
            SHA256          = "Not Checked"
            Extension       = "Unknown"
        }
    }

    $FilePath = Expand-EnvironmentPath $FilePath

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        return [PSCustomObject]@{
            FilePath        = $FilePath
            FileResolved    = "Yes"
            FileExists      = "No"
            SignatureStatus = "Unknown"
            Publisher       = "Unknown"
            SHA256          = "Unknown"
            Extension       = [IO.Path]::GetExtension($FilePath).ToLower()
        }
    }

    $signatureStatus = "Unknown"
    $publisher = "None"
    $hashValue = "Unavailable"

    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        $signatureStatus = $signature.Status

        if ($signature.SignerCertificate) {
            $publisher = $signature.SignerCertificate.Subject
        }
    }
    catch {
        $signatureStatus = "Could not check"
    }

    try {
        $hashValue = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    catch {
        $hashValue = "Could not calculate"
    }

    return [PSCustomObject]@{
        FilePath        = $FilePath
        FileResolved    = "Yes"
        FileExists      = "Yes"
        SignatureStatus = $signatureStatus
        Publisher       = $publisher
        SHA256          = $hashValue
        Extension       = [IO.Path]::GetExtension($FilePath).ToLower()
    }
}

function Get-RiskAssessment {
    param(
        $TrustInfo,
        [string]$CommandText,
        [string]$PersistenceType
    )

    $reasons = New-Object System.Collections.Generic.List[string]
    $severity = "[INFO]"

    $commandSuspicious = $CommandText -match $SuspiciousCommandPattern
    $pathSuspicious = $TrustInfo.FilePath -match $SuspiciousPathPattern
    $isScript = $TrustInfo.Extension -match $ScriptExtensionPattern
    $isUnsigned = $TrustInfo.SignatureStatus -in @("NotSigned", "Unknown", "HashMismatch", "Could not check")

    if ($TrustInfo.FileResolved -eq "No") {
        $reasons.Add("Target file could not be resolved automatically.")
        return [PSCustomObject]@{
            Severity = "[INFO]"
            Reason   = ($reasons -join " ")
        }
    }

    if ($TrustInfo.FileExists -eq "No") {
        $reasons.Add("Persistence entry points to a file that no longer exists.")
        return [PSCustomObject]@{
            Severity = "[MEDIUM]"
            Reason   = ($reasons -join " ")
        }
    }

    if ($isScript -and $pathSuspicious) {
        $severity = "[HIGH]"
        $reasons.Add("Script-based file is located in a higher-risk path.")
    }

    if ($isUnsigned -and $pathSuspicious) {
        if ($severity -ne "[HIGH]") {
            $severity = "[MEDIUM]"
        }

        $reasons.Add("Unsigned or unverifiable file is located in a higher-risk path.")
    }

    if ($commandSuspicious -and $isUnsigned) {
        $severity = "[HIGH]"
        $reasons.Add("Command uses potentially abused execution behavior and target is unsigned/unverified.")
    }

    if ($commandSuspicious -and -not $isUnsigned -and $severity -eq "[INFO]") {
        $severity = "[LOW]"
        $reasons.Add("Command contains behavior commonly abused by malware but target is signed or verified.")
    }

    if ($PersistenceType -and $severity -eq "[INFO]") {
        $reasons.Add("Persistence location checked: $PersistenceType.")
    }

    if ($reasons.Count -eq 0) {
        $reasons.Add("No strong heuristic red flag found.")
    }

    return [PSCustomObject]@{
        Severity = $severity
        Reason   = ($reasons -join " ")
    }
}

function Save-AndDisplayResults {
    param(
        [array]$Items,
        [string]$LogFile,
        [string]$Title,
        [string[]]$Properties
    )

    Write-LogHeader -FilePath $LogFile -Title $Title

    if (-not $Items -or $Items.Count -eq 0) {
        "[OK] No entries found." | Out-File -FilePath $LogFile -Append -Encoding UTF8
        Write-Status "[OK]" "No entries found."
        Write-Host "Saved: $LogFile" -ForegroundColor Cyan
        return
    }

    $Items |
    Select-Object $Properties |
    Format-List |
    Out-File -FilePath $LogFile -Append -Encoding UTF8 -Width 350

    foreach ($item in $Items) {
        Write-Status $item.Severity $item.Reason

        foreach ($property in $Properties) {
            Write-Host ("{0}: {1}" -f $property, $item.$property)
        }

        Write-Host "--------------------------------------------------------------------------------------------" -ForegroundColor DarkGray
    }

    Write-Host "Saved: $LogFile" -ForegroundColor Cyan
}

# ============================================================================================
# VIRUSTOTAL CACHE / MANUAL LOOKUP
# ============================================================================================

function Get-VirusTotalCache {
    if (-not (Test-Path -LiteralPath $CacheFile)) {
        return @{}
    }

    try {
        $raw = Get-Content -LiteralPath $CacheFile -Raw -ErrorAction Stop
        $data = $raw | ConvertFrom-Json -ErrorAction Stop

        $cache = @{}

        foreach ($entry in $data.PSObject.Properties) {
            $cache[$entry.Name] = $entry.Value
        }

        return $cache
    }
    catch {
        return @{}
    }
}

function Save-VirusTotalCache {
    param(
        [hashtable]$Cache
    )

    try {
        $Cache | ConvertTo-Json -Depth 5 | Out-File -FilePath $CacheFile -Encoding UTF8
    }
    catch {
        Write-Status "[LOW]" "Could not save VirusTotal cache."
    }
}

function Get-VirusTotalHashReputation {
    param(
        [string]$SHA256
    )

    if (-not $VirusTotalApiKey) {
        return [PSCustomObject]@{
            Status         = "Skipped - no VirusTotal API key configured"
            DetectionCount = "N/A"
        }
    }

    if (-not (Test-InternetConnection)) {
        return [PSCustomObject]@{
            Status         = "Skipped - no internet connection"
            DetectionCount = "N/A"
        }
    }

    $cache = Get-VirusTotalCache

    if ($cache.ContainsKey($SHA256)) {
        return [PSCustomObject]@{
            Status         = $cache[$SHA256].Status
            DetectionCount = $cache[$SHA256].DetectionCount
        }
    }

    try {
        $headers = @{
            "x-apikey" = $VirusTotalApiKey
        }

        $url = "https://www.virustotal.com/api/v3/files/$SHA256"
        $result = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop

        $stats = $result.data.attributes.last_analysis_stats
        $malicious = $stats.malicious
        $suspicious = $stats.suspicious
        $harmless = $stats.harmless
        $undetected = $stats.undetected

        $status = if ($malicious -gt 0) {
            "Flagged by security engines"
        }
        else {
            "No malicious detections reported"
        }

        $detectionCount = "$malicious malicious / $suspicious suspicious / $harmless harmless / $undetected undetected"

        $cache[$SHA256] = @{
            Status         = $status
            DetectionCount = $detectionCount
            Checked        = (Get-Date).ToString("s")
        }

        Save-VirusTotalCache -Cache $cache

        return [PSCustomObject]@{
            Status         = $status
            DetectionCount = $detectionCount
        }
    }
    catch {
        $message = $_.Exception.Message

        if ($message -match "429") {
            $message = "Rate limited by VirusTotal API"
        }
        elseif ($message -match "404") {
            $message = "Hash not found in VirusTotal database"
        }

        return [PSCustomObject]@{
            Status         = $message
            DetectionCount = "N/A"
        }
    }
}

function Check-FileHashManual {
    Write-Host ""

    if ($VirusTotalApiKey) {
        Write-Status "[INFO]" "A VirusTotal API key is currently configured."
    }
    else {
        Write-Status "[INFO]" "No VirusTotal API key is currently configured. VirusTotal lookups will be skipped unless you set one."
    }

    Write-Host ""
    Write-Host " 1. Enter / replace API key"
    Write-Host " 2. Remove saved API key"
    Write-Host " 3. Continue without changing the API key"

    $keyChoice = Read-Host "`nChoose a number"

    switch ($keyChoice) {
        "1" {
            $newKey = Read-Host "`nPaste your VirusTotal API key"

            if ($newKey) {
                try {
                    @{ ApiKey = $newKey.Trim() } |
                    ConvertTo-Json |
                    Out-File -FilePath $ApiKeyFile -Encoding UTF8 -Force

                    $script:VirusTotalApiKey = $newKey.Trim()

                    Write-Status "[OK]" "API key saved. It will be used for the rest of this session and reloaded automatically next time."
                    Write-Host "Saved to: $ApiKeyFile" -ForegroundColor Cyan
                    Write-Host "Note: this file stores the key in plain text. Do not share your BloodFallen_Logs folder publicly." -ForegroundColor DarkGray
                }
                catch {
                    Write-Status "[MEDIUM]" "Could not save API key: $($_.Exception.Message)"
                }
            }
            else {
                Write-Status "[LOW]" "No key entered. Nothing changed."
            }
        }
        "2" {
            $script:VirusTotalApiKey = ""

            if (Test-Path -LiteralPath $ApiKeyFile) {
                Remove-Item -LiteralPath $ApiKeyFile -Force -ErrorAction SilentlyContinue
            }

            Write-Status "[OK]" "Saved API key removed. VirusTotal lookups will be skipped until a key is set again."
        }
        default {
            # "3" or anything else: leave the key as-is and continue.
        }
    }

    $folder = New-RunLog "ManualHashCheck"
    $logFile = Join-Path $folder "manual_hash_check.txt"

    $path = $null

    while (-not $path) {
        $inputPath = Read-Host "`nPaste the full path of the file (Space + Enter = back to menu)"

        if ($inputPath -eq " ") {
            Write-Status "[INFO]" "Returning to menu."
            return
        }

        if (-not $inputPath -or $inputPath.Trim() -eq "") {
            Write-Status "[LOW]" "File path cannot be empty. Press Enter to try again, or type a single space then Enter to return to the menu."
            continue
        }

        if (-not (Test-Path -LiteralPath $inputPath -PathType Leaf)) {
            Write-Status "[MEDIUM]" "File not found: $inputPath"
            Write-Host "Press Enter to try again, or type a single space then Enter to return to the menu." -ForegroundColor DarkGray
            continue
        }

        $path = $inputPath
    }

    $trust = Get-FileTrustInfo -FilePath $path
    $vt = Get-VirusTotalHashReputation -SHA256 $trust.SHA256

    Write-LogHeader -FilePath $logFile -Title "Manual File Hash Check"

    $result = [PSCustomObject]@{
        FilePath          = $trust.FilePath
        FileExists        = $trust.FileExists
        SignatureStatus   = $trust.SignatureStatus
        Publisher         = $trust.Publisher
        SHA256            = $trust.SHA256
        VirusTotalStatus  = $vt.Status
        DetectionCount    = $vt.DetectionCount
    }

    $result | Format-List | Tee-Object -FilePath $logFile -Append

    Write-Host ""
    Write-Host "Saved: $logFile" -ForegroundColor Cyan
}

# ============================================================================================
# CHECK: SYSTEM INFORMATION
# ============================================================================================

function Check-SystemInformation {
    $folder = New-RunLog "SystemInformation"
    $logFile = Join-Path $folder "system_information.txt"

    Write-LogHeader -FilePath $logFile -Title "System Information"

    $os = Get-CimInstance Win32_OperatingSystem

    $result = [PSCustomObject]@{
        ComputerName       = $env:COMPUTERNAME
        CurrentUser        = $env:USERNAME
        Administrator      = Test-IsAdmin
        WindowsCaption     = $os.Caption
        WindowsVersion     = $os.Version
        WindowsBuild       = $os.BuildNumber
        PowerShellVersion  = $PSVersionTable.PSVersion
        InternetAvailable  = Test-InternetConnection
        DefenderAvailable  = [bool](Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)
    }

    $result | Format-List | Tee-Object -FilePath $logFile -Append

    if ($result.Administrator) {
        Write-Status "[OK]" "Running as Administrator."
    }
    else {
        Write-Status "[!]" "Not running as Administrator. Some checks may be limited. Press A to elevate."
    }

    Write-Host "Saved: $logFile" -ForegroundColor Cyan
}

# ============================================================================================
# CHECK: STARTUP COMMANDS
# ============================================================================================

function Check-StartupCommands {
    $folder = New-RunLog "StartupCommands"
    $logFile = Join-Path $folder "startup_commands.txt"

    $items = @()

    try {
        $items = Get-CimInstance Win32_StartupCommand -ErrorAction Stop | ForEach-Object {
            $target = Get-ExecutablePathFromCommand -Execute $_.Command -Arguments ""
            $trust = Get-FileTrustInfo -FilePath $target
            $risk = Get-RiskAssessment -TrustInfo $trust -CommandText $_.Command -PersistenceType "Startup Command"

            [PSCustomObject]@{
                Severity        = $risk.Severity
                Reason          = $risk.Reason
                Name            = $_.Name
                Command         = $_.Command
                Location        = $_.Location
                User            = $_.User
                TargetFile      = $trust.FilePath
                FileResolved    = $trust.FileResolved
                FileExists      = $trust.FileExists
                SignatureStatus = $trust.SignatureStatus
                Publisher       = $trust.Publisher
                SHA256          = $trust.SHA256
            }
        }
    }
    catch {
        Write-Status "[MEDIUM]" "Could not read startup commands: $($_.Exception.Message)"
    }

    Save-AndDisplayResults -Items $items -LogFile $logFile -Title "Startup Commands" -Properties @(
        "Severity","Reason","Name","Command","Location","User","TargetFile",
        "FileResolved","FileExists","SignatureStatus","Publisher","SHA256"
    )
}

# ============================================================================================
# CHECK: RUN / RUNONCE REGISTRY
# ============================================================================================

function Check-RunRegistry {
    $folder = New-RunLog "RunRegistry"
    $logFile = Join-Path $folder "run_registry.txt"

    $paths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    $items = @()

    foreach ($path in $paths) {
        if (-not (Test-Path $path)) {
            continue
        }

        try {
            $properties = Get-ItemProperty -Path $path -ErrorAction Stop

            foreach ($property in $properties.PSObject.Properties) {
                if ($property.Name -match "^PS") {
                    continue
                }

                $command = [string]$property.Value
                $target = Get-ExecutablePathFromCommand -Execute $command -Arguments ""
                $trust = Get-FileTrustInfo -FilePath $target
                $risk = Get-RiskAssessment -TrustInfo $trust -CommandText $command -PersistenceType "Run/RunOnce Registry"

                $items += [PSCustomObject]@{
                    Severity        = $risk.Severity
                    Reason          = $risk.Reason
                    RegistryPath    = $path
                    ValueName       = $property.Name
                    Command         = $command
                    TargetFile      = $trust.FilePath
                    FileResolved    = $trust.FileResolved
                    FileExists      = $trust.FileExists
                    SignatureStatus = $trust.SignatureStatus
                    Publisher       = $trust.Publisher
                    SHA256          = $trust.SHA256
                }
            }
        }
        catch {
            Write-Status "[LOW]" "Could not read registry path: $path"
        }
    }

    Save-AndDisplayResults -Items $items -LogFile $logFile -Title "Run and RunOnce Registry Entries" -Properties @(
        "Severity","Reason","RegistryPath","ValueName","Command","TargetFile",
        "FileResolved","FileExists","SignatureStatus","Publisher","SHA256"
    )
}

# ============================================================================================
# CHECK: STARTUP FOLDERS
# ============================================================================================

function Check-StartupFolders {
    $folder = New-RunLog "StartupFolders"
    $logFile = Join-Path $folder "startup_folders.txt"

    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    )

    $items = @()

    foreach ($startupPath in $startupFolders) {
        if (-not (Test-Path -LiteralPath $startupPath)) {
            continue
        }

        Get-ChildItem -LiteralPath $startupPath -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $targetPath = $_.FullName

            if ($_.Extension -eq ".lnk") {
                try {
                    $shell = New-Object -ComObject WScript.Shell
                    $shortcut = $shell.CreateShortcut($_.FullName)

                    if ($shortcut.TargetPath) {
                        $targetPath = $shortcut.TargetPath
                    }
                }
                catch {}
            }

            $trust = Get-FileTrustInfo -FilePath $targetPath
            $risk = Get-RiskAssessment -TrustInfo $trust -CommandText $targetPath -PersistenceType "Startup Folder"

            $items += [PSCustomObject]@{
                Severity        = $risk.Severity
                Reason          = $risk.Reason
                StartupFolder   = $startupPath
                ItemName        = $_.Name
                ItemPath        = $_.FullName
                TargetFile      = $trust.FilePath
                FileResolved    = $trust.FileResolved
                FileExists      = $trust.FileExists
                SignatureStatus = $trust.SignatureStatus
                Publisher       = $trust.Publisher
                SHA256          = $trust.SHA256
            }
        }
    }

    Save-AndDisplayResults -Items $items -LogFile $logFile -Title "Startup Folder Entries" -Properties @(
        "Severity","Reason","StartupFolder","ItemName","ItemPath","TargetFile",
        "FileResolved","FileExists","SignatureStatus","Publisher","SHA256"
    )
}

# ============================================================================================
# CHECK: SCHEDULED TASKS
# ============================================================================================

function Check-ScheduledTasks {
    $folder = New-RunLog "ScheduledTasks"
    $logFile = Join-Path $folder "scheduled_tasks.txt"

    $items = @()

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop

        foreach ($task in $tasks) {
            if (-not $task.Actions) {
                continue
            }

            foreach ($action in $task.Actions) {
                $commandText = "$($action.Execute) $($action.Arguments)"
                $target = Get-ExecutablePathFromCommand -Execute $action.Execute -Arguments $action.Arguments
                $trust = Get-FileTrustInfo -FilePath $target
                $risk = Get-RiskAssessment -TrustInfo $trust -CommandText $commandText -PersistenceType "Scheduled Task"

                $items += [PSCustomObject]@{
                    Severity        = $risk.Severity
                    Reason          = $risk.Reason
                    TaskName        = $task.TaskName
                    TaskPath        = $task.TaskPath
                    State           = $task.State
                    Execute         = $action.Execute
                    Arguments       = $action.Arguments
                    TargetFile      = $trust.FilePath
                    FileResolved    = $trust.FileResolved
                    FileExists      = $trust.FileExists
                    SignatureStatus = $trust.SignatureStatus
                    Publisher       = $trust.Publisher
                    SHA256          = $trust.SHA256
                }
            }
        }
    }
    catch {
        Write-Status "[MEDIUM]" "Could not read scheduled tasks: $($_.Exception.Message)"
    }

    Save-AndDisplayResults -Items $items -LogFile $logFile -Title "Scheduled Tasks" -Properties @(
        "Severity","Reason","TaskName","TaskPath","State","Execute","Arguments",
        "TargetFile","FileResolved","FileExists","SignatureStatus","Publisher","SHA256"
    )
}

# ============================================================================================
# CHECK: SERVICES
# ============================================================================================

function Check-Services {
    $folder = New-RunLog "Services"
    $logFile = Join-Path $folder "services.txt"

    $items = @()

    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop

        foreach ($service in $services) {
            $target = Get-ExecutablePathFromCommand -Execute $service.PathName -Arguments ""
            $trust = Get-FileTrustInfo -FilePath $target
            $risk = Get-RiskAssessment -TrustInfo $trust -CommandText $service.PathName -PersistenceType "Windows Service"

            $items += [PSCustomObject]@{
                Severity        = $risk.Severity
                Reason          = $risk.Reason
                Name            = $service.Name
                DisplayName     = $service.DisplayName
                State           = $service.State
                StartMode       = $service.StartMode
                PathName        = $service.PathName
                TargetFile      = $trust.FilePath
                FileResolved    = $trust.FileResolved
                FileExists      = $trust.FileExists
                SignatureStatus = $trust.SignatureStatus
                Publisher       = $trust.Publisher
                SHA256          = $trust.SHA256
            }
        }
    }
    catch {
        Write-Status "[MEDIUM]" "Could not read services: $($_.Exception.Message)"
    }

    Save-AndDisplayResults -Items $items -LogFile $logFile -Title "Windows Services" -Properties @(
        "Severity","Reason","Name","DisplayName","State","StartMode","PathName",
        "TargetFile","FileResolved","FileExists","SignatureStatus","Publisher","SHA256"
    )
}

# ============================================================================================
# CHECK: WMI PERSISTENCE
# ============================================================================================

function Check-WMIPersistence {
    $folder = New-RunLog "WMIPersistence"
    $logFile = Join-Path $folder "wmi_persistence.txt"

    $items = @()

    try {
        Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction Stop | ForEach-Object {
            $commandText = "$($_.Name) $($_.Query)"
            $severity = if ($commandText -match $SuspiciousCommandPattern) { "[MEDIUM]" } else { "[INFO]" }
            $reason = if ($severity -eq "[MEDIUM]") {
                "WMI Event Filter contains potentially abused command behavior."
            }
            else {
                "WMI Event Filter found."
            }

            $items += [PSCustomObject]@{
                Severity = $severity
                Reason   = $reason
                Type     = "Event Filter"
                Name     = $_.Name
                Details  = $_.Query
            }
        }

        Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction Stop | ForEach-Object {
            $target = Get-ExecutablePathFromCommand -Execute $_.CommandLineTemplate -Arguments ""
            $trust = Get-FileTrustInfo -FilePath $target
            $risk = Get-RiskAssessment -TrustInfo $trust -CommandText $_.CommandLineTemplate -PersistenceType "WMI Command Consumer"

            $items += [PSCustomObject]@{
                Severity        = $risk.Severity
                Reason          = $risk.Reason
                Type            = "CommandLineEventConsumer"
                Name            = $_.Name
                Details         = $_.CommandLineTemplate
                TargetFile      = $trust.FilePath
                FileResolved    = $trust.FileResolved
                FileExists      = $trust.FileExists
                SignatureStatus = $trust.SignatureStatus
                Publisher       = $trust.Publisher
                SHA256          = $trust.SHA256
            }
        }

        Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object {
            $items += [PSCustomObject]@{
                Severity = "[INFO]"
                Reason   = "WMI Filter-to-Consumer binding found. Review together with filters and consumers."
                Type     = "FilterToConsumerBinding"
                Name     = "Binding"
                Details  = "Filter: $($_.Filter) | Consumer: $($_.Consumer)"
            }
        }
    }
    catch {
        Write-Status "[LOW]" "Could not fully read WMI persistence objects: $($_.Exception.Message)"
    }

    Save-AndDisplayResults -Items $items -LogFile $logFile -Title "WMI Persistence" -Properties @(
        "Severity","Reason","Type","Name","Details","TargetFile","FileResolved",
        "FileExists","SignatureStatus","Publisher","SHA256"
    )
}

# ============================================================================================
# CHECK: PROCESSES
# ============================================================================================

function Check-SuspiciousProcesses {
    $folder = New-RunLog "Processes"
    $logFile = Join-Path $folder "suspicious_processes.txt"

    $items = @()

    try {
        Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
            if (-not $_.CommandLine) {
                return
            }

            $commandText = $_.CommandLine

            if (($commandText -notmatch $SuspiciousCommandPattern) -and ($commandText -notmatch $SuspiciousPathPattern)) {
                return
            }

            $target = Get-ExecutablePathFromCommand -Execute $_.ExecutablePath -Arguments $_.CommandLine
            $trust = Get-FileTrustInfo -FilePath $target
            $risk = Get-RiskAssessment -TrustInfo $trust -CommandText $commandText -PersistenceType "Running Process"

            $items += [PSCustomObject]@{
                Severity        = $risk.Severity
                Reason          = $risk.Reason
                Name            = $_.Name
                ProcessId       = $_.ProcessId
                ParentProcessId = $_.ParentProcessId
                CommandLine     = $_.CommandLine
                ExecutablePath  = $_.ExecutablePath
                TargetFile      = $trust.FilePath
                FileResolved    = $trust.FileResolved
                FileExists      = $trust.FileExists
                SignatureStatus = $trust.SignatureStatus
                Publisher       = $trust.Publisher
                SHA256          = $trust.SHA256
            }
        }
    }
    catch {
        Write-Status "[MEDIUM]" "Could not inspect processes: $($_.Exception.Message)"
    }

    Save-AndDisplayResults -Items $items -LogFile $logFile -Title "Potentially Suspicious Processes" -Properties @(
        "Severity","Reason","Name","ProcessId","ParentProcessId","CommandLine",
        "ExecutablePath","TargetFile","FileResolved","FileExists","SignatureStatus",
        "Publisher","SHA256"
    )
}

# ============================================================================================
# CHECK: NETWORK
# ============================================================================================

function Check-NetworkConnections {
    $folder = New-RunLog "Network"
    $logFile = Join-Path $folder "network_connections.txt"

    $items = @()

    try {
        Get-NetTCPConnection -State Established -ErrorAction Stop | ForEach-Object {
            $processName = "Unknown"
            $path = $null

            if ($_.OwningProcess -eq 4) {
                $processName = "System"
                $path = "$env:WINDIR\System32\ntoskrnl.exe"
            }
            else {
                try {
                    $process = Get-Process -Id $_.OwningProcess -ErrorAction Stop
                    $processName = $process.ProcessName
                    $path = $process.Path
                }
                catch {
                    $processName = "Process ended or access denied"
                }
            }

            $trust = Get-FileTrustInfo -FilePath $path
            $risk = Get-RiskAssessment -TrustInfo $trust -CommandText "$processName $path" -PersistenceType "Network Connection"

            $items += [PSCustomObject]@{
                Severity        = $risk.Severity
                Reason          = $risk.Reason
                ProcessName     = $processName
                PID             = $_.OwningProcess
                LocalAddress    = $_.LocalAddress
                LocalPort       = $_.LocalPort
                RemoteAddress   = $_.RemoteAddress
                RemotePort      = $_.RemotePort
                TargetFile      = $trust.FilePath
                FileResolved    = $trust.FileResolved
                FileExists      = $trust.FileExists
                SignatureStatus = $trust.SignatureStatus
                Publisher       = $trust.Publisher
            }
        }
    }
    catch {
        Write-Status "[MEDIUM]" "Could not inspect network connections: $($_.Exception.Message)"
    }

    Save-AndDisplayResults -Items $items -LogFile $logFile -Title "Established Network Connections" -Properties @(
        "Severity","Reason","ProcessName","PID","LocalAddress","LocalPort","RemoteAddress",
        "RemotePort","TargetFile","FileResolved","FileExists","SignatureStatus","Publisher"
    )
}

# ============================================================================================
# CHECK: RECENT SUSPICIOUS FILES
# ============================================================================================

function Check-RecentSuspiciousFiles {
    $folder = New-RunLog "RecentSuspiciousFiles"
    $logFile = Join-Path $folder "recent_suspicious_files.txt"

    $scanPaths = @(
        $env:LOCALAPPDATA,
        $env:APPDATA,
        "$env:LOCALAPPDATA\Temp",
        "C:\ProgramData",
        "$env:USERPROFILE\Downloads"
    )

    $cutoff = (Get-Date).AddDays(-$RecentFileDays)
    $items = @()

    Write-Host ""
    Write-Status "[INFO]" "Scanning $($scanPaths.Count) locations for files modified in the last $RecentFileDays day(s)."
    Write-Host "This recurses through AppData/ProgramData/Downloads and can take a few minutes on systems with lots of files - it is not frozen." -ForegroundColor DarkGray

    foreach ($scanPath in $scanPaths) {
        if (-not (Test-Path -LiteralPath $scanPath)) {
            continue
        }

        Write-Host ""
        Write-Status "[INFO]" "Scanning: $scanPath ..."

        try {
            $files = Get-ChildItem -LiteralPath $scanPath -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $_.LastWriteTime -ge $cutoff -and $_.Extension -match $SuspiciousExtensionPattern
            } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First $RecentFileLimitPerFolder

            foreach ($file in $files) {
                $trust = Get-FileTrustInfo -FilePath $file.FullName
                $risk = Get-RiskAssessment -TrustInfo $trust -CommandText $file.FullName -PersistenceType "Recent Suspicious File Scan"

                if ($risk.Severity -eq "[INFO]") {
                    $risk = [PSCustomObject]@{
                        Severity = "[LOW]"
                        Reason   = "Recently modified executable/script-related file found in user-writable location."
                    }
                }

                $items += [PSCustomObject]@{
                    Severity        = $risk.Severity
                    Reason          = $risk.Reason
                    Name            = $file.Name
                    FullName        = $file.FullName
                    Extension       = $file.Extension
                    SizeKB          = [math]::Round($file.Length / 1KB, 2)
                    Created         = $file.CreationTime
                    LastWrite       = $file.LastWriteTime
                    SignatureStatus = $trust.SignatureStatus
                    Publisher       = $trust.Publisher
                    SHA256          = $trust.SHA256
                }
            }

            Write-Status "[OK]" "Done: $scanPath ($($files.Count) matching file(s) found)"
        }
        catch {
            Write-Status "[LOW]" "Could not fully scan: $scanPath"
        }
    }

    Write-Host ""
    Save-AndDisplayResults -Items $items -LogFile $logFile -Title "Recent Suspicious Files" -Properties @(
        "Severity","Reason","Name","FullName","Extension","SizeKB","Created","LastWrite",
        "SignatureStatus","Publisher","SHA256"
    )
}

# ============================================================================================
# CHECK: DEFENDER
# ============================================================================================

function Check-DefenderStatus {
    $folder = New-RunLog "DefenderStatus"
    $logFile = Join-Path $folder "defender_status.txt"

    Write-LogHeader -FilePath $logFile -Title "Microsoft Defender Status"

    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        Write-Status "[LOW]" "Microsoft Defender cmdlets are unavailable."
        "Microsoft Defender cmdlets are unavailable." | Out-File $logFile -Append
        return
    }

    try {
        Get-MpComputerStatus |
        Select-Object AMRunningMode, AntivirusEnabled, AntispywareEnabled,
        RealTimeProtectionEnabled, AntivirusSignatureLastUpdated,
        QuickScanAge, FullScanAge |
        Format-List |
        Tee-Object -FilePath $logFile -Append
    }
    catch {
        Write-Status "[MEDIUM]" "Could not read Defender status: $($_.Exception.Message)"
    }
}

function Check-DefenderExclusions {
    $folder = New-RunLog "DefenderExclusions"
    $logFile = Join-Path $folder "defender_exclusions.txt"

    Write-LogHeader -FilePath $logFile -Title "Microsoft Defender Exclusions"

    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Status "[LOW]" "Microsoft Defender preferences cmdlet is unavailable."
        return
    }

    try {
        $pref = Get-MpPreference -ErrorAction Stop

        $result = [PSCustomObject]@{
            ExclusionPath      = ($pref.ExclusionPath -join "; ")
            ExclusionProcess   = ($pref.ExclusionProcess -join "; ")
            ExclusionExtension = ($pref.ExclusionExtension -join "; ")
            ExclusionIpAddress = ($pref.ExclusionIpAddress -join "; ")
        }

        $result | Format-List | Tee-Object -FilePath $logFile -Append

        if ($pref.ExclusionPath -or $pref.ExclusionProcess -or $pref.ExclusionExtension) {
            Write-Status "[LOW]" "Defender exclusions exist. Review whether they are expected."
        }
        else {
            Write-Status "[OK]" "No Defender exclusions found."
        }
    }
    catch {
        Write-Status "[MEDIUM]" "Could not read Defender exclusions: $($_.Exception.Message)"
    }
}

function Run-DefenderQuickScan {
    if (-not (Get-Command Start-MpScan -ErrorAction SilentlyContinue)) {
        Write-Status "[LOW]" "Microsoft Defender scan command is unavailable."
        return
    }

    try {
        Start-MpScan -ScanType QuickScan -ErrorAction Stop
        Write-Status "[OK]" "Microsoft Defender Quick Scan started."
    }
    catch {
        Write-Status "[MEDIUM]" "Could not start Quick Scan: $($_.Exception.Message)"
    }
}

function Run-DefenderFullScan {
    if (-not (Get-Command Start-MpScan -ErrorAction SilentlyContinue)) {
        Write-Status "[LOW]" "Microsoft Defender scan command is unavailable."
        return
    }

    try {
        Start-MpScan -ScanType FullScan -ErrorAction Stop
        Write-Status "[OK]" "Microsoft Defender Full Scan started."
    }
    catch {
        Write-Status "[MEDIUM]" "Could not start Full Scan: $($_.Exception.Message)"
    }
}

# ============================================================================================
# CHECK: HOSTS / PROXY / DNS
# ============================================================================================

function Check-NetworkSettings {
    $folder = New-RunLog "NetworkSettings"
    $logFile = Join-Path $folder "network_settings.txt"

    Write-LogHeader -FilePath $logFile -Title "Hosts File, Proxy, and DNS Settings"

    $hostsPath = "$env:WINDIR\System32\drivers\etc\hosts"

    "`n=== HOSTS FILE ===" | Tee-Object -FilePath $logFile -Append

    if (Test-Path -LiteralPath $hostsPath) {
        $hostsEntries = Get-Content -LiteralPath $hostsPath |
        Where-Object {
            $_.Trim() -and -not $_.Trim().StartsWith("#") -and $_ -notmatch "^\s*127\.0\.0\.1\s+localhost" -and $_ -notmatch "^\s*::1\s+localhost"
        }

        if ($hostsEntries) {
            Write-Status "[LOW]" "Custom hosts file entries found. Review them."
            $hostsEntries | Tee-Object -FilePath $logFile -Append
        }
        else {
            Write-Status "[OK]" "No unusual hosts file entries found."
        }
    }

    "`n=== PROXY SETTINGS ===" | Tee-Object -FilePath $logFile -Append

    try {
        $proxy = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction Stop

        $proxyResult = [PSCustomObject]@{
            ProxyEnable   = $proxy.ProxyEnable
            ProxyServer   = $proxy.ProxyServer
            AutoConfigURL = $proxy.AutoConfigURL
        }

        $proxyResult | Format-List | Tee-Object -FilePath $logFile -Append

        if ($proxy.ProxyEnable -eq 1 -or $proxy.AutoConfigURL) {
            Write-Status "[LOW]" "Proxy or automatic proxy configuration is enabled. Review if expected."
        }
        else {
            Write-Status "[OK]" "No active user proxy configuration found."
        }
    }
    catch {
        Write-Status "[LOW]" "Could not read proxy settings."
    }

    "`n=== DNS SETTINGS ===" | Tee-Object -FilePath $logFile -Append

    try {
        Get-DnsClientServerAddress -AddressFamily IPv4 |
        Select-Object InterfaceAlias, ServerAddresses |
        Format-Table -AutoSize |
        Tee-Object -FilePath $logFile -Append
    }
    catch {
        Write-Status "[LOW]" "Could not read DNS settings."
    }

    Write-Host "Saved: $logFile" -ForegroundColor Cyan
}

# ============================================================================================
# CHECK: BROWSER EXTENSION INVENTORY
# ============================================================================================

function Check-BrowserExtensions {
    $folder = New-RunLog "BrowserExtensions"
    $logFile = Join-Path $folder "browser_extensions_inventory.txt"

    Write-LogHeader -FilePath $logFile -Title "Browser Extension Inventory"

    $browserPaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    )

    foreach ($browserPath in $browserPaths) {
        if (-not (Test-Path -LiteralPath $browserPath)) {
            continue
        }

        Write-Host ""
        Write-Status "[INFO]" "Checking extension folders: $browserPath"

        "Browser Path: $browserPath" | Out-File $logFile -Append

        Get-ChildItem -LiteralPath $browserPath -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "Default|Profile \d+" } |
        ForEach-Object {
            $extensionPath = Join-Path $_.FullName "Extensions"

            if (Test-Path -LiteralPath $extensionPath) {
                Get-ChildItem -LiteralPath $extensionPath -Directory -Force -ErrorAction SilentlyContinue |
                Select-Object @{
                    Name = "BrowserProfile"
                    Expression = { $_.Parent.Parent.Name }
                }, @{
                    Name = "ExtensionID"
                    Expression = { $_.Name }
                }, FullName |
                Format-Table -AutoSize |
                Out-File $logFile -Append
            }
        }
    }

    Write-Status "[INFO]" "This inventory does not read cookies, passwords, tokens, or browser history."
    Write-Host "Saved: $logFile" -ForegroundColor Cyan
}

# ============================================================================================
# FULL REPORT / EXPORT
# ============================================================================================

function Create-FullReport {
    $folder = New-RunLog "FullReport"
    $logFile = Join-Path $folder "full_report.txt"

    Write-LogHeader -FilePath $logFile -Title "Full Evidence Report"

    "This report is evidence-only and does not modify the system." | Out-File $logFile -Append
    "" | Out-File $logFile -Append

    try {
        "`n=== SYSTEM INFORMATION ===" | Out-File $logFile -Append
        Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, BuildNumber, LastBootUpTime |
        Format-List |
        Out-File $logFile -Append
    }
    catch {}

    try {
        "`n=== STARTUP COMMANDS ===" | Out-File $logFile -Append
        Get-CimInstance Win32_StartupCommand |
        Select-Object Name, Command, Location, User |
        Format-Table -Wrap |
        Out-File $logFile -Append -Width 350
    }
    catch {}

    try {
        "`n=== RUN / RUNONCE REGISTRY ===" | Out-File $logFile -Append
        Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" |
        Format-List |
        Out-File $logFile -Append -Width 350
    }
    catch {}

    try {
        "`n=== SCHEDULED TASKS ===" | Out-File $logFile -Append
        Get-ScheduledTask | ForEach-Object {
            foreach ($action in $_.Actions) {
                [PSCustomObject]@{
                    TaskName  = $_.TaskName
                    TaskPath  = $_.TaskPath
                    State     = $_.State
                    Execute   = $action.Execute
                    Arguments = $action.Arguments
                }
            }
        } |
        Format-Table -Wrap |
        Out-File $logFile -Append -Width 350
    }
    catch {}

    try {
        "`n=== SERVICES ===" | Out-File $logFile -Append
        Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, PathName |
        Format-Table -Wrap |
        Out-File $logFile -Append -Width 350
    }
    catch {}

    try {
        "`n=== ESTABLISHED NETWORK CONNECTIONS ===" | Out-File $logFile -Append
        Get-NetTCPConnection -State Established |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
        Format-Table -Wrap |
        Out-File $logFile -Append -Width 350
    }
    catch {}

    try {
        "`n=== DEFENDER STATUS ===" | Out-File $logFile -Append
        Get-MpComputerStatus |
        Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled,
        AntivirusSignatureLastUpdated, QuickScanAge, FullScanAge |
        Format-List |
        Out-File $logFile -Append
    }
    catch {}

    Write-Status "[OK]" "Full evidence report created."
    Write-Host "Saved: $logFile" -ForegroundColor Cyan
}

function Export-LogsZip {
    $stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $zipPath = Join-Path (Split-Path $BaseDir -Parent) "BloodFallen_Logs_$stamp.zip"

    $logs = Get-ChildItem -LiteralPath $BaseDir -Force

    if (-not $logs) {
        Write-Status "[LOW]" "No logs found yet. Run at least one check first."
        return
    }

    try {
        Compress-Archive -Path "$BaseDir\*" -DestinationPath $zipPath -Force -ErrorAction Stop
        Write-Status "[OK]" "Logs exported successfully."
        Write-Host $zipPath -ForegroundColor Cyan
    }
    catch {
        Write-Status "[MEDIUM]" "Could not export logs: $($_.Exception.Message)"
    }
}

# ============================================================================================
# MAIN MENU
# ============================================================================================

$running = $true

while ($running) {
    Write-Header

    if (Test-IsAdmin) {
        Write-Status "[OK]" "Administrator mode detected."
    }
    else {
        Write-Status "[LOW]" "Not running as Administrator. Some checks may be limited. Press A to elevate."
    }
	
	if (-not (Test-IsAdmin)) {
        Write-Host " A. Restart BloodFallen as Administrator" -ForegroundColor Yellow
    }
	
    Write-Host ""
    Write-Host " 1. System information and environment check"

    

    Write-Host " 2. Check startup commands"
    Write-Host " 3. Check Run / RunOnce registry entries"
    Write-Host " 4. Check Startup folder entries"
    Write-Host " 5. Check scheduled tasks"
    Write-Host " 6. Check Windows services"
    Write-Host " 7. Check WMI persistence"
    Write-Host " 8. Check suspicious running processes"
    Write-Host " 9. Check established network connections"
    Write-Host "10. Scan recently modified suspicious files"
    Write-Host "11. Check Microsoft Defender status"
    Write-Host "12. Check Microsoft Defender exclusions"
    Write-Host "13. Run Microsoft Defender Quick Scan"
    Write-Host "14. Run Microsoft Defender Full Scan"
    Write-Host "15. Check hosts file, proxy, and DNS settings"
    Write-Host "16. Manual file hash, signature, and VirusTotal lookup"
    Write-Host "17. Browser extension inventory"
    Write-Host "18. Create full evidence report"
    Write-Host "19. Export all logs as ZIP"
    Write-Host "20. Open logs folder"
    Write-Host " 0. Exit"

    $choice = Read-Host "`nChoose a number"

    switch ($choice) {
		"A"  { Restart-AsAdministrator }
        "a"  { Restart-AsAdministrator }
        "1"  { Check-SystemInformation; Pause-Menu }
        "2"  { Check-StartupCommands; Pause-Menu }
        "3"  { Check-RunRegistry; Pause-Menu }
        "4"  { Check-StartupFolders; Pause-Menu }
        "5"  { Check-ScheduledTasks; Pause-Menu }
        "6"  { Check-Services; Pause-Menu }
        "7"  { Check-WMIPersistence; Pause-Menu }
        "8"  { Check-SuspiciousProcesses; Pause-Menu }
        "9"  { Check-NetworkConnections; Pause-Menu }
        "10" { Check-RecentSuspiciousFiles; Pause-Menu }
        "11" { Check-DefenderStatus; Pause-Menu }
        "12" { Check-DefenderExclusions; Pause-Menu }
        "13" { Run-DefenderQuickScan; Pause-Menu }
        "14" { Run-DefenderFullScan; Pause-Menu }
        "15" { Check-NetworkSettings; Pause-Menu }
        "16" { Check-FileHashManual; Pause-Menu }
        "17" { Check-BrowserExtensions; Pause-Menu }
        "18" { Create-FullReport; Pause-Menu }
        "19" { Export-LogsZip; Pause-Menu }
        "20" { Start-Process $BaseDir }
        "0"  {
            Write-Host ""
            Write-Host "Exiting BloodFallen Forensic Triage Toolkit..." -ForegroundColor Yellow
            Start-Sleep -Milliseconds 700
            $running = $false
        }
        default {
            Write-Status "[Error]" "Invalid choice."
            Start-Sleep -Seconds 1
        }
    }
}