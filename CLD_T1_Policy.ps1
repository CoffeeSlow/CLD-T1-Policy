param([switch]$SkipPause)

$ErrorActionPreference = "SilentlyContinue"
$Host.UI.RawUI.WindowTitle = "CLD T1 Policy"
$Host.UI.RawUI.BackgroundColor = "Black"
Clear-Host

$suspiciousFindings = [System.Collections.Generic.List[PSObject]]::new()
$suspiciousFindings.Add([PSCustomObject]@{
    Type      = "Context"
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    PC        = $env:COMPUTERNAME
    User      = $env:USERNAME
    Score     = $null
})

function Write-ColoredLine {
    param ([string]$Text, [ConsoleColor]$Color = 'White')
    $oldColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    Write-Host $Text
    $Host.UI.RawUI.ForegroundColor = $oldColor
}

function Wait-ForEnter {
    param([string]$Message = "Press Enter to Continue")
    Write-Host ""
    Write-ColoredLine ">> $Message" Cyan
    do {
        $key = [System.Console]::ReadKey($true)
    } while ($key.Key -ne "Enter")
}

function Show-CustomLoadingBar {
    $cr = [char]13
    Write-Host ""
    for ($p = 0; $p -le 100; $p += 5) {
        $filled = [math]::Floor($p / 2.5)
        $empty = 40 - $filled
        $bar = "#" * $filled + "-" * $empty
        $percentage = "{0,3}" -f $p
        if ($p -eq 100) { $color = "Green" } else { $color = "Red" }
        Write-Host -NoNewline ("{0}[ {1} ] {2}% " -f $cr, $bar, $percentage) -ForegroundColor $color
        Start-Sleep -Milliseconds 50
    }
    Write-Host ""
    Write-Host ""
}

function Write-BoxedHeader {
    param([string]$Title, [string]$Subtitle = "")
    $innerWidth = 62
    $border = "+" + ("-" * $innerWidth) + "+"
    $titlePadding = [math]::Floor(($innerWidth - $Title.Length) / 2)
    $titleLine = " " * $titlePadding + $Title + " " * ($innerWidth - $titlePadding - $Title.Length)
    Write-Host ""
    Write-ColoredLine $border Cyan
    Write-Host "|" -NoNewline -ForegroundColor Cyan
    Write-Host $titleLine -NoNewline
    Write-Host "|" -ForegroundColor Cyan
    if ($Subtitle) {
        $subtitlePadding = [math]::Floor(($innerWidth - $Subtitle.Length) / 2)
        $leftPadding = " " * $subtitlePadding
        $rightPadding = " " * ($innerWidth - $subtitlePadding - $Subtitle.Length)
        $splitPoint = 14
        $firstHalf = $Subtitle.Substring(0, [math]::Min($splitPoint, $Subtitle.Length))
        $secondHalf = if ($Subtitle.Length -gt $splitPoint) { $Subtitle.Substring($splitPoint) } else { "" }
        Write-Host "|" -NoNewline -ForegroundColor Cyan
        Write-Host ($leftPadding + $firstHalf) -NoNewline -ForegroundColor White
        Write-Host ($secondHalf + $rightPadding) -NoNewline -ForegroundColor White
        Write-Host "|" -ForegroundColor Cyan
    }
    Write-ColoredLine $border Cyan
    Write-Host ""
}

function Write-Section {
    param([string]$Title, [string[]]$Lines)
    Write-Host ""
    Write-ColoredLine " +- $Title" DarkGray
    foreach ($line in $Lines) {
        if ($line -match "^SUCCESS") {
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-ColoredLine ("OK " + ($line -replace '^SUCCESS: ', '')) Green
        }
        elseif ($line -match "^FAILURE") {
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-ColoredLine ("X " + ($line -replace '^FAILURE: ', '')) Red
        }
        elseif ($line -match "^WARNING") {
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-ColoredLine ("W " + ($line -replace '^WARNING: ', '')) Yellow
        }
        elseif ($line -match "SUSPICIOUS") {
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-ColoredLine $line Red
        }
        else {
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-ColoredLine $line White
        }
    }
    Write-ColoredLine " +-" DarkGray
}

function Write-StepResult {
    param([int]$Success, [int]$Total, [int]$StepNumber)
    $rate = if ($Total -gt 0) { [math]::Round(($Success / $Total) * 100, 0) } else { 100 }
    $color = if ($rate -eq 100) { "Green" } elseif ($rate -ge 80) { "Yellow" } else { "Red" }
    $icon = if ($rate -eq 100) { "OK" } elseif ($rate -ge 80) { "W" } else { "X" }
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host " $icon Step $StepNumber Result: " -NoNewline -ForegroundColor $color
    Write-Host "$rate% " -NoNewline -ForegroundColor $color
    Write-Host "($Success/$Total checks passed)" -ForegroundColor Gray
    Write-Host "============================================================" -ForegroundColor DarkGray
}

function Start-FileWatcher {
    param([string]$LogFile)
    try {
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = "C:\"
        $watcher.IncludeSubdirectories = $true
        $watcher.EnableRaisingEvents = $true
        $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastAccess
        $wshell = New-Object -ComObject WScript.Shell
        $action = {
            $path = $Event.SourceEventArgs.FullPath
            $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Add-Content -Path $LogFile -Value "[$time] Opened: $path" -ErrorAction SilentlyContinue
            $wshell.Popup("This application was opened: $path", 5, "File Access", 64)
        }
        Register-ObjectEvent -InputObject $watcher -EventName Created -SourceIdentifier "FileCreated_$PID" -Action $action | Out-Null
        Register-ObjectEvent -InputObject $watcher -EventName Changed -SourceIdentifier "FileChanged_$PID" -Action $action | Out-Null
    } catch {
        Write-ColoredLine " W File watcher setup failed." Yellow
    }
}

# ===============================
# TITLE SCREEN
# ===============================
Clear-Host
Write-Host ""
Write-Host "  ____ _     ____    _____ _   ____   ___  _     ___ ______   __" -ForegroundColor White
Write-Host " / ___| |   |  _ \  |_   _/ | |  _ \ / _ \| |   |_ _/ ___\ \ / /" -ForegroundColor White
Write-Host "| |   | |   | | | |   | | | | | |_) | | | | |    | | |    \ V / " -ForegroundColor White
Write-Host "| |___| |___| |_| |   | | | | |  __/| |_| | |___ | | |___  | |  " -ForegroundColor White
Write-Host " \____|_____|____/    |_| |_| |_|    \___/|_____|___\____| |_|  " -ForegroundColor White
Write-Host ""

Write-ColoredLine "============================================================" Cyan
Write-ColoredLine " discord.gg/cldx" White
Write-ColoredLine "============================================================" Cyan
Write-Host ""
Write-ColoredLine "=== CLD T1 POLICY ===" Cyan
Write-ColoredLine "Pass all the steps." White
Write-ColoredLine "Admin required." White
Write-Host ""

# CPU Detection
$cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
if ($cpu -and $cpu.NumberOfCores -ge 4 -and $cpu.MaxClockSpeed -ge 2500) {
    Write-Host "CPU: " -NoNewline -ForegroundColor White
    Write-Host "$($cpu.Name)" -ForegroundColor Gray
    Write-ColoredLine "Good performance." Green
} else {
    Write-Host "CPU: " -NoNewline -ForegroundColor White
    Write-Host "$($cpu.Name)" -ForegroundColor Gray
    Write-ColoredLine "May impact performance." Yellow
}
Write-Host ""

# GPU Detection
$gpu = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Select-Object -First 1
$gpuName = $gpu.Name
$goodGPUs = @("RTX 30", "RTX 40", "RX 6000", "RX 7000")
$gpuIsGood = $goodGPUs | Where-Object { $gpuName -like "*$_*" }
if ($gpuIsGood) {
    Write-Host "GPU: " -NoNewline -ForegroundColor White
    Write-Host "$gpuName" -ForegroundColor Gray
    Write-ColoredLine "Good performance." Green
} else {
    Write-Host "GPU: " -NoNewline -ForegroundColor White
    Write-Host "$gpuName" -ForegroundColor Gray
    Write-ColoredLine "May impact performance." Yellow
}
Write-Host ""

# Credits
Write-ColoredLine "=== Credits ===" Cyan
Write-ColoredLine "Created by CLD Justice Department" DarkBlue
Write-Host ""

# Wait to Start
if (-not $SkipPause) {
    Write-ColoredLine ">> Press Enter to Start" Cyan
    do {
        $key = [System.Console]::ReadKey($true)
    } while ($key.Key -ne "Enter")
}

# ===============================
# STEP 1/2 - SYSTEM CHECK
# ===============================
Clear-Host
New-Item -ItemType Directory -Path "C:\ToolsCLD" -ErrorAction SilentlyContinue | Out-Null
$logFile = "C:\ToolsCLD\file_log.txt"
Start-FileWatcher -LogFile $logFile

Write-BoxedHeader "STEP 1/2: SYSTEM CHECK" "Verifying security configuration..."
Show-CustomLoadingBar

$modulesOutput = @()
$cpuGpuOutput = @()
$memoryIntegrityOutput = @()
$defenderOutput = @()
$exclusionsOutput = @()
$processOutput = @()
$keyAuthOutput = @()

# Module Check
$defaultModules = @("Microsoft.PowerShell.Archive", "Microsoft.PowerShell.Diagnostics", "Microsoft.PowerShell.Host", "Microsoft.PowerShell.LocalAccounts", "Microsoft.PowerShell.Management", "Microsoft.PowerShell.Security", "Microsoft.PowerShell.Utility", "PackageManagement", "PowerShellGet", "PSReadLine", "Pester", "ThreadJob")
$protectedModule = "Microsoft.PowerShell.Operation.Validation"
$modulesPath = "C:\Program Files\WindowsPowerShell\Modules"
$modules = Get-ChildItem $modulesPath -Directory -ErrorAction SilentlyContinue

foreach ($module in $modules) {
    $moduleName = $module.Name
    if ($moduleName -eq $protectedModule) {
        $modulesOutput += "SUCCESS: Protected module verified."
    } elseif ($moduleName -notin $defaultModules) {
        $modulesOutput += "FAILURE: Unauthorized module: $moduleName"
    }
}
if (-not $modulesOutput) { $modulesOutput += "SUCCESS: No unauthorized modules." }

# CPU & GPU Detections
try {
    $cpuName = Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name
    if ($cpuName) { $cpuGpuOutput += "SUCCESS: CPU detected -> $cpuName" }
    $gpus = Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name
    foreach ($g in $gpus) {
        $cpuGpuOutput += "SUCCESS: GPU detected -> $g"
    }
} catch {
    $cpuGpuOutput += "WARNING: Unable to query CPU/GPU information."
}

# Windows Defender
try {
    $def = Get-MpComputerStatus -ErrorAction Stop
    if ($def.AntivirusEnabled -and $def.RealTimeProtectionEnabled) {
        $defenderOutput += "SUCCESS: Windows Defender real-time protection enabled."
    } else {
        $defenderOutput += "FAILURE: Windows Defender not active."
    }
} catch {
    $defenderOutput += "WARNING: Defender status check failed."
}

# Defender Exclusions
try {
    $exclusions = (Get-MpPreference).ExclusionPath
    if (-not $exclusions) {
        $exclusionsOutput += "SUCCESS: No Defender exclusions."
    } else {
        $exclusionsOutput += "FAILURE: Defender exclusions detected."
        foreach ($excl in $exclusions) {
            $exclusionsOutput += " -> $excl"
            $suspiciousFindings.Add([PSCustomObject]@{Type = "DefenderExclusion"; Path = $excl})
        }
    }
} catch {
    $exclusionsOutput += "WARNING: Cannot check exclusions."
}

# Memory Integrity
try {
    $enabled = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction Stop
    if ($enabled -eq 1) {
        $memoryIntegrityOutput += "SUCCESS: Memory Integrity enabled."
    } else {
        $memoryIntegrityOutput += "FAILURE: Memory Integrity disabled."
    }
} catch {
    $memoryIntegrityOutput += "WARNING: Memory Integrity status unavailable."
}

# Process Scan
$suspicious = @(
    "matcha","matrix","loader","map","severe","isabelle",
    "photon","dx9ware","melatonin","evolve","atlanta",
    "serotonin","aimmy","valex","solara","xeno",
    "monkeyaim","thunderaim","thunderclient","celex",
    "celery","zarora","juju","nezure","fluxus",
    "clumsy","myst","horizon","tupical","cloudy",
    "volt","potassium","wave","cosmic","volcano",
    "isaeva","synapse","velocity","seliware","bunni",
    "sirhurt","delta","cryptic","vega","codex",
    "hydrogen","macsploit","opiumware","rbxcli","ronin",
    "kiciahook","snaw"
)

$foundProc = $false
Get-Process | ForEach-Object {
    foreach ($s in $suspicious) {
        if ($_.Name.ToLower() -like "*$s*") {
            $processOutput += "FAILURE: Suspicious process $($_.Name) (PID $($_.Id))"
            $foundProc = $true
            $suspiciousFindings.Add([PSCustomObject]@{Type = "SuspiciousProcess"; Name = $_.Name})
        }
    }
}
if (-not $foundProc) {
    $processOutput += "SUCCESS: No suspicious processes detected."
}

# KeyAuth Check
try {
    $keyPath = "C:\ProgramData\KeyAuth\debug"
    if (-not (Get-ChildItem $keyPath -Directory -ErrorAction SilentlyContinue)) {
        $keyAuthOutput += "SUCCESS: No KeyAuth cheat folders."
    } else {
        $keyAuthOutput += "FAILURE: Suspicious KeyAuth folders detected."
    }
} catch {
    $keyAuthOutput += "SUCCESS: KeyAuth area clean."
}

# VM Check
$vmOutput = @()
$vmDetected = $false
$vmName = ""

# Check registry keys
$vmRegistryKeys = @(
    @{Path="HKLM:\SOFTWARE\VMware, Inc.\VMware Tools"; Name="VMware"},
    @{Path="HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions"; Name="VirtualBox"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"; Name="Hyper-V"},
    @{Path="HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0"; Name="QEMU/VirtualBox"}
)
foreach ($key in $vmRegistryKeys) {
    if (Test-Path $key.Path) {
        $vmDetected = $true
        $vmName = $key.Name
        break
    }
}

# Check VM processes
if (-not $vmDetected) {
    $vmProcesses = @("vmtoolsd","vmwaretray","vmwareuser","vboxservice","vboxtray","qemu-ga","vmsrvc","vmusrvc","xenservice","vmacthlp")
    foreach ($vmp in $vmProcesses) {
        if (Get-Process -Name $vmp -ErrorAction SilentlyContinue) {
            $vmDetected = $true
            $vmName = $vmp
            break
        }
    }
}

# Check WMI BIOS/hardware
if (-not $vmDetected) {
    try {
        $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop | Select-Object -ExpandProperty Manufacturer
        $board = Get-CimInstance Win32_BaseBoard -ErrorAction Stop | Select-Object -ExpandProperty Manufacturer
        $vmStrings = @("VMware","VirtualBox","QEMU","Xen","Microsoft Corporation","innotek","bochs","KVM")
        foreach ($str in $vmStrings) {
            if ($bios -like "*$str*" -or $board -like "*$str*") {
                if ($str -ne "Microsoft Corporation") {
                    $vmDetected = $true
                    $vmName = $str
                    break
                }
            }
        }
    } catch {}
}

if ($vmDetected) {
    $vmOutput += "FAILURE: Virtual machine detected: $vmName"
} else {
    $vmOutput += "SUCCESS: No virtual machine detected."
}

# Display Step 1 Results
Write-Section "Modules" $modulesOutput
Write-Section "CPU & GPU Detections" $cpuGpuOutput
Write-Section "Windows Defender" $defenderOutput
Write-Section "Defender Exclusions" $exclusionsOutput
Write-Section "Memory Integrity" $memoryIntegrityOutput
Write-Section "Process Scan" $processOutput
Write-Section "KeyAuth Check" $keyAuthOutput
Write-Section "Virtual Machine Check" $vmOutput

$allResults1 = $modulesOutput + $cpuGpuOutput + $defenderOutput + $exclusionsOutput + $memoryIntegrityOutput + $processOutput + $keyAuthOutput + $vmOutput
$total1 = ($allResults1 | Where-Object { $_ -match '^(SUCCESS|FAILURE|WARNING)' }).Count
$success1 = ($allResults1 | Where-Object { $_ -match '^SUCCESS' }).Count
if ($total1 -eq 0) { $total1 = 7 }
Write-StepResult -Success $success1 -Total $total1 -StepNumber 1

# Wait for Step 2
Wait-ForEnter -Message "Press Enter to Continue to Step 2"

# ===============================
# STEP 2/2 - PROCESS EXPLORER
# ===============================
Clear-Host

Write-BoxedHeader "STEP 2/2: PROCESS EXPLORER" "Launching Microsoft Process Explorer..."
Write-ColoredLine "INSTRUCTIONS: Review all processes, scroll to bottom, then close the window." Yellow
Show-CustomLoadingBar

$processNames = @("procexp32", "procexp64", "procexp64a")
$runningPE = Get-Process -ErrorAction SilentlyContinue | Where-Object { $processNames -contains $_.ProcessName.ToLower() }
if ($runningPE) {
    Write-ColoredLine " OK Terminated existing Process Explorer instances." Green
    $runningPE | ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch {} }
    Start-Sleep -Seconds 1
} else {
    Write-ColoredLine " OK No existing Process Explorer instances found." Green
}

$baseFolder = "C:\ToolsCLD"
$extractFolder = Join-Path $baseFolder "ProcessExplorer"
$zipUrl = "https://download.sysinternals.com/files/ProcessExplorer.zip"
$zipPath = Join-Path $baseFolder "ProcessExplorer.zip"

if (-not (Test-Path $baseFolder)) {
    New-Item -ItemType Directory -Path $baseFolder -ErrorAction Stop | Out-Null
}
if (-not (Test-Path $extractFolder)) {
    New-Item -ItemType Directory -Path $extractFolder -ErrorAction Stop | Out-Null
}

# Download if not exists
$actualExe = Get-ChildItem -Path $extractFolder -Filter "procexp64.exe" -Recurse | Select-Object -First 1
if (-not $actualExe) {
    Write-ColoredLine " Downloading Process Explorer..." Cyan
    try {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
        Write-ColoredLine " OK Downloaded Process Explorer." Green
        
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractFolder)
        Write-ColoredLine " OK Extracted Process Explorer." Green
        
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    } catch {
        Write-ColoredLine " X Download failed." Red
    }
} else {
    Write-ColoredLine " OK Process Explorer already available." Green
}

$actualExe = Get-ChildItem -Path $extractFolder -Filter "procexp64.exe" -Recurse | Select-Object -First 1
$peOutput = @()
if ($actualExe) {
    Write-ColoredLine " OK Launching Process Explorer..." Green
    Write-ColoredLine " Review all processes, then close when done." Yellow
    $proc = Start-Process -FilePath $actualExe.FullName -PassThru
    if ($proc) {
        Wait-Process -Id $proc.Id -ErrorAction SilentlyContinue
    }
    $peOutput += "SUCCESS: Process Explorer review completed."
} else {
    $peOutput += "FAILURE: procexp64.exe not found."
}

Write-Section "Process Explorer Analysis" $peOutput

$total2 = ($peOutput | Where-Object { $_ -match '^(SUCCESS|FAILURE|WARNING)' }).Count
$success2 = ($peOutput | Where-Object { $_ -match '^SUCCESS' }).Count
if ($total2 -eq 0) { $total2 = 1 }
Write-StepResult -Success $success2 -Total $total2 -StepNumber 2

# ===============================
# FINAL RESULTS
# ===============================
Unregister-Event -SourceIdentifier "FileCreated_$PID" -ErrorAction SilentlyContinue
Unregister-Event -SourceIdentifier "FileChanged_$PID" -ErrorAction SilentlyContinue

$overallTotal = $total1 + $total2
$overallSuccess = $success1 + $success2
$overallRate = [math]::Round(($overallSuccess / $overallTotal) * 100, 0)
$overallColor = if ($overallRate -eq 100) { "Green" } elseif ($overallRate -ge 80) { "Yellow" } else { "Red" }

Write-Host ""
Write-ColoredLine "============================================================" Cyan
Write-Host " OVERALL SUCCESS RATE: " -NoNewline -ForegroundColor White
Write-Host "$overallRate%" -NoNewline -ForegroundColor $overallColor
Write-Host " ($overallSuccess/$overallTotal checks passed)" -ForegroundColor Gray
Write-ColoredLine "============================================================" Cyan

Write-Host ""
Write-ColoredLine ">> Press Enter to exit" Cyan
do {
    $key = [System.Console]::ReadKey($true)
} while ($key.Key -ne "Enter")

exit
