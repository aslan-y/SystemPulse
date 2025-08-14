#Requires -Version 5.1

<#
.SYNOPSIS
    Umfassender Windows-Systemdiagnosebericht mit Gesundheitscheck und Problemidentifikation

.DESCRIPTION
    Erstellt einen vollständigen Systembericht mit Diagnose für Windows-Systeme. Erfasst detaillierte
    Informationen zu:
    - Hardware (CPU, RAM, Grafikkarten, Festplatten)
    - System (OS, BIOS, Uptime)
    - Netzwerk (Adapter, Konnektivität, DNS)
    - Software (Dienste, Autostart)
    - Sicherheit (Defender, Firewall, Anmeldeversuche)
    - Performance (CPU/RAM-Auslastung, Top-Prozesse)
    - Ereignisse (Systemfehler, Warnungen)
    
    Der Bericht enthält automatische Gesundheitschecks und visuelle Statusanzeigen (🟢🟡🔴).

.NOTES
    Author:        Yasin Aslan
    Version:       1.0
    LastModified:  2025-08-12
    Requires:      PowerShell 5.1 oder höher, Administratorrechte
    OS Support:    Windows 10/11, Windows Server 2016+
    # Copyright (c) 2025 Yasin Aslan
    # MIT License - https://opensource.org/licenses/MIT

.EXAMPLE
    .\HWINFO.ps1
    Führt das Skript aus und erstellt einen vollständigen Bericht auf dem Desktop

.OUTPUTS
    Eine formatierte Textdatei (Systembericht_FULL.txt) auf dem Desktop des Benutzers
    mit chronologisch angeordneten Systemdiagnosedaten.
    
.LINK
    https://github.com/aslan-y/HWINFO
#>

#region SETUP & PREREQUISITES
# Admin-Check
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) { 
    Write-Error "❌ Dieses Skript muss mit Adminrechten ausgeführt werden!" 
    exit 
}

# Speicherpfad & Encoding
$basePath = [Environment]::GetFolderPath('Desktop')
$defaultFilename = "Systembericht_FULL.txt"
$defaultPath = Join-Path -Path $basePath -ChildPath $defaultFilename
$Encoding = 'utf8BOM'

# Speicherort-Dialog anzeigen
try {
    Add-Type -AssemblyName System.Windows.Forms
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "Textdateien (*.txt)|*.txt|Alle Dateien (*.*)|*.*"
    $saveFileDialog.Title = "Systembericht speichern unter..."
    $saveFileDialog.FileName = $defaultFilename
    $saveFileDialog.InitialDirectory = $basePath
    $saveFileDialog.DefaultExt = "txt"
    
    # Dialog anzeigen und Ergebnis überprüfen
    if ($saveFileDialog.ShowDialog() -eq 'OK') {
        $OutputPath = $saveFileDialog.FileName
    } else {
        # Bei Abbruch Standardpfad verwenden
        Write-Host "Dialogauswahl abgebrochen. Verwende Standardpfad: $defaultPath" -ForegroundColor Yellow
        $OutputPath = $defaultPath
    }
} catch {
    # Bei Fehler im Dialog Standardpfad verwenden
    Write-Warning "Fehler beim Öffnen des Speicherdialogs: $_"
    Write-Host "Verwende Standardpfad: $defaultPath" -ForegroundColor Yellow
    $OutputPath = $defaultPath
}
#endregion

#region HELPER FUNCTIONS
function Get-SystemData {
    param (
        [string]$Command,
        [scriptblock]$ScriptBlock
    )
    
    try { 
        Write-Progress -Activity "Sammle Systeminformationen" -Status $Command
        & $ScriptBlock 
    }
    catch { 
        Write-Warning "❌ Fehler bei '$Command': $_"
        return "❌ Fehler bei '$Command'" 
    }
}

function Write-Status {
    param(
        [string]$Text,
        [string]$Level
    )
    
    switch ($Level) {
        'OK'     { Write-Host "🟢 $Text" -ForegroundColor Green; return "🟢 $Text" }
        'WARN'   { Write-Host "🟡 $Text" -ForegroundColor Yellow; return "🟡 $Text" }
        'CRIT'   { Write-Host "🔴 $Text" -ForegroundColor Red; return "🔴 $Text" }
        default  { Write-Host "$Text"; return "$Text" }
    }
}

# Mehrsprachige & robuste Counter-Abfrage
function Get-CounterSafe {
    param(
        [string[]]$PossibleNames,  # Mögliche Counter-Namen
        [string]$Label,            # Beschriftung
        [string]$Unit = ''         # Einheit
    )

    # Direkte Counter-Abfrage für CPU (schneller und zuverlässiger)
    if ($Label -eq 'CPU-Auslastung') {
        try {
            # Alternative Methode über WMI für CPU-Last
            $cpuLoad = (Get-WmiObject -Class Win32_Processor | 
                        Measure-Object -Property LoadPercentage -Average).Average
            
            if ($null -ne $cpuLoad -and $cpuLoad -gt 0) {
                return "${Label}: $cpuLoad $Unit"
            }
        } catch {
            # Fehler ignorieren und fortfahren mit normaler Methode
        }
    }

    # Standard-Methode für alle anderen Counter
    foreach ($name in $PossibleNames) {
        try {
            # Direkte Abfrage ohne vorherige Prüfung (schneller)
            $value = (Get-Counter $name -ErrorAction Stop -MaxSamples 1).CounterSamples.CookedValue
            if ($null -eq $value) { continue }
            if ($Label -like '*RAM*' -and [math]::Round($value,0) -eq 0) { continue }
            return "${Label}: $([math]::Round($value, 2)) $Unit"
        }
        catch { continue }
    }
    
    return "${Label}: Nicht verfügbar"
}

#endregion

#region DATA COLLECTION
$SystemData = @{}

# Allgemeine Systeminformationen
$SystemData.SystemInfo = Get-SystemData "Systeminformationen" {
    $out = @()

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $out += "💻 Hersteller: $($cs.Manufacturer)"
    $out += "🖥 Modell: $($cs.Model)"

    $bios = Get-CimInstance -ClassName Win32_BIOS
    $out += "📜 BIOS-Version: $($bios.SMBIOSBIOSVersion)"
    $out += "📅 BIOS-Datum: $($bios.ReleaseDate.ToShortDateString())"

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $out += "🪟 Betriebssystem: $($os.Caption)"
    $out += "🏗 Build: $($os.BuildNumber)"
    
    # Robustere Methode für den letzten Neustart
    try {
        $lastBootTime = $os.LastBootUpTime
        if ($lastBootTime) {
            $lastBootTimeFormatted = [DateTime]::ParseExact($lastBootTime.Substring(0,14), 'yyyyMMddHHmmss', $null)
            $out += "🕒 Letzter Neustart: $($lastBootTimeFormatted.ToString('yyyy-MM-dd HH:mm:ss'))"
        } else {
            $uptime = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
            $out += "🕒 Letzter Neustart: $((Get-Date).AddSeconds(-$uptime.TotalSeconds).ToString('yyyy-MM-dd HH:mm:ss'))"
        }
    } catch {
        # Alternative Methode
        try {
            $uptime = [TimeSpan]::FromSeconds((Get-WmiObject -Class Win32_PerfFormattedData_PerfOS_System).SystemUptime)
            $out += "🕒 Letzter Neustart: $((Get-Date).AddSeconds(-$uptime.TotalSeconds).ToString('yyyy-MM-dd HH:mm:ss'))"
        } catch {
            $out += "🕒 Letzter Neustart: Nicht verfügbar"
        }
    }

    $out -join "`n"
}

# CPU, RAM und GPU Details
$SystemData.HardwareDetails = Get-SystemData "Hardware-Details" {
    $out = @()
    
    # CPU-Details
    $cpu = Get-WmiObject Win32_Processor
    $out += "--- CPU ---"
    $out += "Prozessor: $($cpu.Name)"
    $out += "Kerne: $($cpu.NumberOfCores) | Logische Prozessoren: $($cpu.NumberOfLogicalProcessors)"
    $out += "Max. Taktrate: $([math]::Round($cpu.MaxClockSpeed/1000, 2)) GHz"
    
    # RAM-Details
    $totalRAM = (Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    $ramSlots = Get-WmiObject Win32_PhysicalMemory
    $out += "`n--- RAM ---"
    $out += "Gesamt: $([math]::Round($totalRAM, 2)) GB"
    $out += "Belegte Slots: $($ramSlots.Count)"
    foreach ($slot in $ramSlots) {
        $out += "  - $([math]::Round($slot.Capacity/1GB, 2)) GB @ $($slot.Speed) MHz ($($slot.Manufacturer))"
    }
    
    # GPU-Details
    $gpus = Get-WmiObject Win32_VideoController
    $out += "`n--- Grafikkarten ---"
    foreach ($gpu in $gpus) {
        $memGB = if ($gpu.AdapterRAM) { [math]::Round($gpu.AdapterRAM/1GB, 2) } else { "N/A" }
        $out += "  - $($gpu.Name) - RAM: $memGB GB"
        $out += "    Auflösung: $($gpu.CurrentHorizontalResolution)x$($gpu.CurrentVerticalResolution)"
    }
    
    $out -join "`n"
}

# Performance
$SystemData.PerformanceInfo = Get-SystemData "Performance" {
    $out = @()
    $out += Write-Status (Get-CounterSafe -PossibleNames @(
        '\Processor(_Total)\% Processor Time',
        '\Prozessor(_Total)\% Prozessorzeit',
        '\Prozessorinformation(_Total)\% Prozessorzeit',
        '\Processor Information(_Total)\% Processor Time',
        '\Processor(*_Total)\% Processor Time',
        '\Prozessor(*_Total)\% Prozessorzeit'
    ) -Label 'CPU-Auslastung' -Unit '%') 'OK'
    $out += Write-Status (Get-CounterSafe -PossibleNames @(
        '\Memory\Available MBytes',
        '\Arbeitsspeicher\Verfügbare MB'
    ) -Label 'Verfügbarer RAM' -Unit 'MB') 'OK'

    $out += "Prozesse gesamt: $((Get-Process).Count)"
    $out -join "`n"
}

# Top-Verbraucher
$SystemData.TopProcesses = Get-SystemData "Top-Prozesse" {
    "`n-- CPU Top 5 --`n" +
    (Get-Process | 
        Sort-Object CPU -Descending | 
        Select-Object -First 5 Name,CPU |
        Format-Table -AutoSize | 
        Out-String) +
    "`n-- RAM Top 5 --`n" +
    (Get-Process | 
        Sort-Object WS -Descending | 
        Select-Object -First 5 Name,@{N='RAM(MB)';E={[math]::Round($_.WS/1MB,1)}} |
        Format-Table -AutoSize | 
        Out-String)
}

# Festplattenstatus + SMART
$SystemData.DiskHealth = Get-SystemData "Festplattenstatus" {
    $list = @()
    $drives = Get-PhysicalDisk
    
    foreach ($d in $drives) {
        $health = if ($d.HealthStatus -ne 'Healthy') { 'CRIT' } else { 'OK' }
        $list += Write-Status "$($d.FriendlyName) - $($d.Size/1GB -as [int])GB - Zustand: $($d.HealthStatus)" $health
    }
    
    $list -join "`n"
}

# Laufwerksbelegung (ohne Temp)
$SystemData.DiskUsage = Get-SystemData "Festplattenbelegung" {
    Get-PSDrive -PSProvider FileSystem | 
        Where-Object { $_.Name -ne 'Temp' } |
        Select-Object Name,
                      @{N='Gesamt(GB)';E={[math]::Round($_.Used/1GB + $_.Free/1GB,2)}},
                      @{N='Belegt(GB)';E={[math]::Round($_.Used/1GB,2)}},
                      @{N='Frei(GB)';E={[math]::Round($_.Free/1GB,2)}},
                      @{N='Frei (%)';E={[math]::Round(($_.Free/($_.Used+$_.Free))*100,2)}} |
        Format-Table -AutoSize | 
        Out-String
}

# Netzwerk-Check
$SystemData.NetworkTest = Get-SystemData "Netzwerkdiagnose" {
    $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop | Select-Object -First 1
    $pingGW = Test-Connection -ComputerName $gw -Count 2 -Quiet
    $gwStatus = if ($pingGW) { 
        Write-Status "Gateway $gw erreichbar" 'OK' 
    } else { 
        Write-Status "Gateway $gw nicht erreichbar" 'CRIT' 
    }

    $pingExt = Test-Connection -ComputerName 8.8.8.8 -Count 2 -Quiet
    $extStatus = if ($pingExt) { 
        Write-Status "Internet (8.8.8.8) erreichbar" 'OK' 
    } else { 
        Write-Status "Internet nicht erreichbar" 'CRIT' 
    }

    "$gwStatus`n$extStatus"
}

# Netzwerkadapter-Details
$SystemData.NetworkAdapters = Get-SystemData "Netzwerkadapter" {
    $out = @()
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    
    foreach ($adapter in $adapters) {
        $out += "--- $($adapter.Name) ($($adapter.InterfaceDescription)) ---"
        $out += "Status: $($adapter.Status) | Geschwindigkeit: $($adapter.LinkSpeed)"
        
        $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex
        $ipv4 = $ipConfig | Where-Object { $_.AddressFamily -eq "IPv4" }
        $ipv6 = $ipConfig | Where-Object { $_.AddressFamily -eq "IPv6" }
        
        if ($ipv4) { $out += "IPv4: $($ipv4.IPAddress)" }
        if ($ipv6) { $out += "IPv6: $($ipv6[0].IPAddress)" }
        
        $dns = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex).ServerAddresses
        if ($dns) { $out += "DNS-Server: $($dns -join ', ')" }
        
        # Bei WLAN zusätzliche Infos
        if ($adapter.Name -like "*Wi-Fi*" -or $adapter.Name -like "*WLAN*") {
            try {
                $wlanInfo = (netsh wlan show interfaces) -match 'SSID|Signal|Funktyp|Kanal'
                $out += "`nWLAN-Details:"
                $out += $wlanInfo
            } catch {
                $out += "WLAN-Details nicht verfügbar"
            }
        }
        
        $out += ""
    }
    
    $out -join "`n"
}

# Dienste-Check
$SystemData.Services = Get-SystemData "Dienste-Status" {
    $excludedServices = @('McmSvc', 'WaaSMedicSvc')
    $stopped = Get-Service -ErrorAction SilentlyContinue |
        Where-Object {
            $_.StartType -eq 'Automatic' -and
            $_.Status -ne 'Running' -and
            $_.Name -notin $excludedServices
        }

    if ($stopped.Count -gt 0) {
        $statusMsg = Write-Status "Automatische Dienste nicht gestartet:" 'WARN'
        
        # In der Konsole anzeigen (eine Zeile pro Dienst für bessere Übersichtlichkeit)
        foreach ($svc in $stopped) {
            Write-Host "  - $($svc.Name): $($svc.DisplayName)" -ForegroundColor Yellow
        }
        
        # Für die Berichtsdatei das Tabellenformat verwenden
        $warns = $stopped | 
                 Select-Object Name,DisplayName,Status |
                 Format-Table -AutoSize | 
                 Out-String
        
        # Formatierte Ausgabe für den Bericht zurückgeben
        "$statusMsg`n$warns"
    }
    else {
        Write-Status "Alle automatischen Dienste laufen" 'OK'
    }
}

# Startprogramme
$SystemData.StartupItems = Get-SystemData "Startprogramme" {
    $regStartup = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $userStartup = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    $startupFolder = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue
    
    $out = @("--- System-Autostart ---")
    foreach ($item in $regStartup.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }) {
        $out += "  - $($item.Name): $($item.Value)"
    }
    
    $out += "`n--- Benutzer-Autostart ---"
    if ($userStartup) {
        foreach ($item in $userStartup.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }) {
            $out += "  - $($item.Name): $($item.Value)"
        }
    } else {
        $out += "  Keine Einträge gefunden"
    }
    
    $out += "`n--- Autostart-Ordner ---"
    if ($startupFolder) {
        foreach ($item in $startupFolder) {
            $out += "  - $($item.Name)"
        }
    } else {
        $out += "  Keine Einträge gefunden"
    }
    
    $out -join "`n"
}

# Wichtige Systemereignisse
$SystemData.SystemEvents = Get-SystemData "Systemereignisse" {
    $criticalEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        Level = 1,2
    } -MaxEvents 10 -ErrorAction SilentlyContinue
    
    if ($criticalEvents -and $criticalEvents.Count -gt 0) {
        $statusMsg = Write-Status "Kritische Systemereignisse gefunden:" 'WARN'
        
        # Für die Konsole
        foreach ($evt in $criticalEvents) {
            $level = if ($evt.Level -eq 1) { "Kritisch" } else { "Fehler" }
            Write-Host "  - [$level] $($evt.TimeCreated): $($evt.Message.Split([Environment]::NewLine)[0])" -ForegroundColor Yellow
        }
        
        # Für den Bericht
        $eventsTable = $criticalEvents | 
            Select-Object TimeCreated, 
                @{N='Typ';E={if ($_.Level -eq 1) { "Kritisch" } elseif ($_.Level -eq 2) { "Fehler" } else { "Warnung" }}},
                ID, 
                @{N='Quelle';E={$_.ProviderName}},
                @{N='Nachricht';E={$_.Message.Split([Environment]::NewLine)[0]}} |
            Format-Table -AutoSize -Wrap | 
            Out-String
        
        "$statusMsg`n$eventsTable"
    } else {
        Write-Status "Keine kritischen Systemereignisse in den letzten Tagen" 'OK'
    }
}


# Sicherheits-Log (fehlgeschlagene Anmeldungen)
$SystemData.SecurityLog = Get-SystemData "Anmeldefehler" {
    $events = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4625)]]" -MaxEvents 5 -ErrorAction SilentlyContinue
    
    if ($events -and $events.Count -gt 0) {
        $statusMsg = Write-Status "Letzte fehlgeschlagene Logons:" 'WARN'
        
        # In der Konsole anzeigen (eine Zeile pro Eintrag für bessere Übersichtlichkeit)
        foreach ($evt in $events) {
            Write-Host "  - $($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')): $($evt.Properties[5].Value)" -ForegroundColor Yellow
        }
        
        # Für die Berichtsdatei
        $fails = $events |
                 Select-Object TimeCreated, @{N='Konto';E={$_.Properties[5].Value}} |
                 Format-Table -AutoSize | 
                 Out-String
        
        # Formatierte Ausgabe für den Bericht zurückgeben
        "$statusMsg`n$fails"
    }
    else {
        Write-Status "Keine fehlgeschlagenen Logons gefunden" 'OK'
    }
}

# Microsoft Defender Status
$SystemData.DefenderStatus = Get-SystemData "Windows Defender" {
    $out = @()
    
    try {
        # Hauptstatus abrufen
        $mpStatus = Get-MpComputerStatus
        
        # Allgemeiner Status
        $rtStatus = if ($mpStatus.RealTimeProtectionEnabled) { 'OK' } else { 'CRIT' }
        $out += Write-Status "Echtzeit-Schutz: $($mpStatus.RealTimeProtectionEnabled)" $rtStatus
        
        $amStatus = if ($mpStatus.AntivirusEnabled) { 'OK' } else { 'CRIT' }
        $out += Write-Status "Antivirus aktiviert: $($mpStatus.AntivirusEnabled)" $amStatus
        
        # Signaturen & Updates
        $signatureAge = $mpStatus.AntivirusSignatureAge
        $sigStatus = if ($signatureAge -gt 7) { 'CRIT' } elseif ($signatureAge -gt 3) { 'WARN' } else { 'OK' }
        $out += Write-Status "Signatur-Alter: $signatureAge Tage" $sigStatus
        $out += "Signatur-Version: $($mpStatus.AntivirusSignatureVersion)"
        $out += "Letzte Signatur-Aktualisierung: $($mpStatus.AntispywareSignatureLastUpdated)"

        # Scan-Informationen
        $scanAge = if ($mpStatus.FullScanAge -eq 0 -or $mpStatus.FullScanAge -gt 10000) { 
            Write-Host "  - Kein Scan-Datum verfügbar, möglicherweise nie durchgeführt" -ForegroundColor Yellow
            "Nie durchgeführt" 
        } else { 
            $mpStatus.FullScanAge 
        }

        if ($scanAge -eq "Nie durchgeführt") {
            $out += Write-Status "Letzter Komplett-Scan: $scanAge" 'WARN'
        } else {
            $scanStatus = if ([int]$scanAge -gt 30) { 'WARN' } elseif ([int]$scanAge -gt 90) { 'CRIT' } else { 'OK' }
            $out += Write-Status "Letzter Komplett-Scan vor: $scanAge Tagen" $scanStatus
        }

        # Zusätzliche Schutzmechanismen
        $out += "`n--- Schutzfunktionen ---"
        $tamperStatus = if ($mpStatus.IsTamperProtected) { 'OK' } else { 'WARN' }
        $out += Write-Status "Manipulationsschutz: $($mpStatus.IsTamperProtected)" $tamperStatus
        
        $behaviorStatus = if ($mpStatus.BehaviorMonitorEnabled) { 'OK' } else { 'WARN' }
        $out += Write-Status "Verhaltensüberwachung: $($mpStatus.BehaviorMonitorEnabled)" $behaviorStatus
        
        $iotStatus = if ($mpStatus.IoavProtectionEnabled) { 'OK' } else { 'WARN' }
        $out += Write-Status "Schutz vor internetbasierten Bedrohungen: $($mpStatus.IoavProtectionEnabled)" $iotStatus
        
        # Firewall-Status über NetSecurity abrufen
        $out += "`n--- Firewall-Status ---"
        $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        if ($fwProfiles) {
            foreach ($firewallProfile in $fwProfiles) {
                $fwStatus = if ($firewallProfile.Enabled) { 'OK' } else { 'CRIT' }
                $out += Write-Status "Firewall ($($firewallProfile.Name)): $($firewallProfile.Enabled)" $fwStatus
            }
        } else {
            $out += "Firewall-Status: Nicht verfügbar"
        }
        
        # Aktuelle Bedrohungen
        $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue
        if ($threats -and $threats.Count -gt 0) {
            $out += "`n--- Erkannte Bedrohungen ---"
            foreach ($threat in $threats | Sort-Object InitialDetectionTime -Descending | Select-Object -First 5) {
                $out += Write-Status "Bedrohung: $($threat.ThreatName) (Status: $($threat.ThreatStatusDescription))" 'CRIT'
                Write-Host "  - Erkannt am: $($threat.InitialDetectionTime)" -ForegroundColor Red
                Write-Host "  - Ressourcen: $($threat.Resources)" -ForegroundColor Red
            }
            
            # Für den Bericht
            $threatTable = $threats | 
                Sort-Object InitialDetectionTime -Descending | 
                Select-Object -First 5 ThreatName, InitialDetectionTime, ThreatStatusDescription |
                Format-Table -AutoSize | 
                Out-String
            $out += $threatTable
        } else {
            $out += Write-Status "Keine aktiven Bedrohungen erkannt" 'OK'
        }
    } catch {
        $out += "❌ Fehler beim Abrufen des Defender-Status: $_"
        Write-Warning "Fehler beim Abrufen des Defender-Status: $_"
    }
    
    $out -join "`n"
}

# Windows-Updates Status
$SystemData.WindowsUpdates = Get-SystemData "Windows-Updates" {
    $updates = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
    $lastUpdate = $updates | Select-Object -First 1 -ExpandProperty InstalledOn
    $daysSinceUpdate = (New-TimeSpan -Start $lastUpdate -End (Get-Date)).Days
    
    $updateStatus = if ($daysSinceUpdate -gt 60) { 'CRIT' } elseif ($daysSinceUpdate -gt 30) { 'WARN' } else { 'OK' }
    
    # Bessere Beschreibung für die Konsole
    $statusText = "Windows-Updates: Letztes Update vor $daysSinceUpdate Tagen"
    $statusMsg = Write-Status $statusText $updateStatus
    
    # Detailliertere Information zum letzten Update in der Konsole
    $lastUpdateInfo = $updates | Select-Object -First 1
    Write-Host "  - Update-Paket: $($lastUpdateInfo.HotFixID)" -ForegroundColor $(if ($updateStatus -eq 'OK') { 'Green' } elseif ($updateStatus -eq 'WARN') { 'Yellow' } else { 'Red' })
    Write-Host "  - Installiert am: $($lastUpdateInfo.InstalledOn.ToString('yyyy-MM-dd'))" -ForegroundColor $(if ($updateStatus -eq 'OK') { 'Green' } elseif ($updateStatus -eq 'WARN') { 'Yellow' } else { 'Red' })
    
    # Information für die Textdatei mit zusätzlichen Details
    "$statusMsg`n`n-- Letzte 10 Windows-Updates --`n" + ($updates | Format-Table -AutoSize | Out-String)
}

# BitLocker Status
$SystemData.BitLockerStatus = Get-SystemData "BitLocker" {
    $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($volumes) {
        $volumes | Select-Object MountPoint, VolumeStatus, EncryptionMethod, 
                  @{N='Verschlüsselt(%)';E={$_.EncryptionPercentage}} | 
                  Format-Table -AutoSize | Out-String
    } else {
        "BitLocker nicht verfügbar oder keine verschlüsselten Laufwerke"
    }
}

# Installierte Software (Top 20)
$SystemData.InstalledSoftware = Get-SystemData "Installierte Software" {
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
    Where-Object DisplayName -ne $null | 
    Sort-Object DisplayName | 
    Select-Object -First 20 DisplayName, DisplayVersion, Publisher |
    Format-Table -AutoSize | Out-String
}

# Offene Ports & Verbindungen
$SystemData.NetworkConnections = Get-SystemData "Netzwerkverbindungen" {
    $netstat = netstat -ano | Select-Object -Skip 4
    "Aktive Verbindungen:`n" + ($netstat | Out-String)
}

# Active Directory und Gruppenrichtlinien Status
$SystemData.ActiveDirectoryInfo = Get-SystemData "Active Directory & GPO" {
    $out = @()
    $isInDomain = $false
    
    # 1. Domänenmitgliedschaft prüfen
    try {
        $computerSystem = Get-WmiObject Win32_ComputerSystem
        $isInDomain = $computerSystem.PartOfDomain
        
        if ($isInDomain) {
            $domainStatus = 'OK'
            $out += Write-Status "Computer ist Mitglied der Domäne: $($computerSystem.Domain)" $domainStatus
            $out += "Domänenrolle: $((Get-DomänenrolleText $computerSystem.DomainRole))"
            
            # Domänen-Funktionsebene und Infrastruktur
            try {
                # Prüfen, ob das AD-Modul verfügbar ist
                if (Get-Module -ListAvailable -Name ActiveDirectory) {
                    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                    
                    $domainInfo = Get-ADDomain -ErrorAction SilentlyContinue
                    if ($domainInfo) {
                        $out += "`n--- Domänen-Informationen ---"
                        $out += "Domänenname (NetBIOS): $($domainInfo.NetBIOSName)"
                        $out += "Domänenname (DNS): $($domainInfo.DNSRoot)"
                        $out += "Funktionsebene: $($domainInfo.DomainMode)"
                        $out += "PDC-Emulator: $($domainInfo.PDCEmulator)"
                        
                        # Domain Controller erreichbar
                        $dcTest = Test-Connection -ComputerName $domainInfo.PDCEmulator -Count 1 -Quiet -ErrorAction SilentlyContinue
                        $dcStatus = if ($dcTest) { 'OK' } else { 'CRIT' }
                        $out += Write-Status "PDC-Erreichbarkeit: $dcTest" $dcStatus
                    }
                    
                    # Computerkontodetails
                    $computerObj = Get-ADComputer $env:COMPUTERNAME -Properties * -ErrorAction SilentlyContinue
                    if ($computerObj) {
                        $out += "`n--- Computer-Kontoinformationen ---"
                        $out += "Erstellungsdatum: $($computerObj.Created)"
                        $out += "Letzte Kennwortänderung: $($computerObj.PasswordLastSet)"
                        
                        # Computerkonto-Status prüfen
                        $accountStatus = if ($computerObj.Enabled) { 'OK' } else { 'CRIT' }
                        $out += Write-Status "Konto aktiv: $($computerObj.Enabled)" $accountStatus
                        
                        # Letzte Anmeldung/Kontakt
                        $lastLogon = if ($computerObj.LastLogonDate) { $computerObj.LastLogonDate } else { "Nie" }
                        $out += "Letzte Anmeldung: $lastLogon"
                    }
                    
                    # Domain-Vertrauensstellungen
                    $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
                    if ($trusts) {
                        $out += "`n--- Domänen-Vertrauensstellungen ---"
                        foreach ($trust in $trusts) {
                            $out += "Vertrauensstellung zu: $($trust.Name) (Typ: $($trust.TrustType), Richtung: $($trust.TrustDirection))"
                        }
                    }
                } else {
                    $out += "`nHinweis: Das ActiveDirectory-Modul ist nicht installiert. Erweiterte AD-Informationen sind nicht verfügbar."
                }
            }
            catch {
                $out += "Fehler beim Abrufen von AD-Informationen: $_"
            }
            
            # 2. Gruppenrichtlinien-Status
            $out += "`n--- Gruppenrichtlinien-Status ---"
            
            # GPO-Basisprüfung mit RSOP
            try {
                # GPO Last Refresh
                $gpoLastRefresh = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine" -Name RefreshTimeLast -ErrorAction SilentlyContinue
                if ($gpoLastRefresh) {
                    $lastRefreshTime = [DateTime]::FromFileTime($gpoLastRefresh.RefreshTimeLast)
                    $timeSinceRefresh = (Get-Date) - $lastRefreshTime
                    $refreshStatus = if ($timeSinceRefresh.TotalHours -gt 24) { 'WARN' } else { 'OK' }
                    $out += Write-Status "Letzte GPO-Aktualisierung: $($lastRefreshTime) (vor $([math]::Round($timeSinceRefresh.TotalHours, 1)) Stunden)" $refreshStatus
                }
                
                # GPResult-Ausgabe für wichtige Einstellungen
                $gpResultOutput = & gpresult /r
                
                # Gruppenrichtlinien-Fehlermeldungen suchen
                $gpErrors = $gpResultOutput | Where-Object { $_ -match "Fehler" -or $_ -match "nicht angewendet" }
                if ($gpErrors) {
                    $out += Write-Status "Gruppenrichtlinien-Fehler gefunden:" 'WARN'
                    foreach ($gpError in $gpErrors) {
                        $out += "  - $gpError"
                    }
                }
                
                # Angewendete Computerrichtlinien
                $computerPolicies = @()
                $inComputerSection = $false
                
                foreach ($line in $gpResultOutput) {
                    if ($line -match "Angewendete Gruppenrichtlinien für Computer") {
                        $inComputerSection = $true
                        continue
                    }
                    if ($inComputerSection -and $line -match "^    ") {
                        $computerPolicies += $line.Trim()
                    }
                    if ($inComputerSection -and $line -match "Angewendete Gruppenrichtlinien für Benutzer") {
                        $inComputerSection = $false
                    }
                }
                
                if ($computerPolicies.Count -gt 0) {
                    $out += "`nAngewendete Computer-Gruppenrichtlinien:"
                    foreach ($policy in $computerPolicies) {
                        $out += "  - $policy"
                    }
                } else {
                    $out += "Keine Computer-Gruppenrichtlinien angewendet"
                }
                
                # Sicherheitsrelevante Einstellungen prüfen
                $out += "`n--- Sicherheitsrelevante GPO-Einstellungen ---"
                
                # Lokale Administratorgruppe (über WMI)
                try {
                    $adminGroup = Get-WmiObject Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'"
                    $adminMembers = Get-WmiObject Win32_GroupUser -Filter "GroupComponent=""Win32_Group.Domain='$($env:COMPUTERNAME)',Name='$($adminGroup.Name)'"""
                    
                    $adminCount = $adminMembers.Count
                    $adminStatus = if ($adminCount -gt 3) { 'WARN' } else { 'OK' }
                    $out += Write-Status "Lokale Administratoren: $adminCount Mitglieder" $adminStatus
                    
                    if ($adminCount -gt 0) {
                        $out += "Lokale Administratorgruppe enthält:"
                        foreach ($admin in $adminMembers) {
                            $partComponent = $admin.PartComponent
                            if ($partComponent -match 'Name="(.*?)"') {
                                $out += "  - $($Matches[1])"
                            }
                        }
                    }
                } catch {
                    $out += "Fehler beim Abrufen der lokalen Administratoren: $_"
                }
                
                # Kennwortrichtlinie prüfen
                try {
                    $pwdPolicy = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ErrorAction SilentlyContinue
                    if ($pwdPolicy) {
                        $requireStrongPwd = if (($pwdPolicy.RequireStrongKey -eq 1) -or ($pwdPolicy.RequireSignOrSeal -eq 1)) { $true } else { $false }
                        $pwdStatus = if ($requireStrongPwd) { 'OK' } else { 'WARN' }
                        $out += Write-Status "Starke Kennwortrichtlinie: $requireStrongPwd" $pwdStatus
                    }
                } catch {
                    $out += "Fehler beim Abrufen der Kennwortrichtlinie: $_"
                }
                
                # Offlinefiles (für Laptops relevant)
                try {
                    $offlineFiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache" -Name Enabled -ErrorAction SilentlyContinue
                    if ($offlineFiles) {
                        $out += "Offlinefiles Status: " + $(if ($offlineFiles.Enabled -eq 1) { "Aktiviert" } else { "Deaktiviert" })
                    }
                } catch {
                    # Ignorieren wenn nicht vorhanden
                }
                
                # Detaillierte GPO-Ausgabe generieren
                $gpoDetailsFile = "$env:TEMP\GPODetails.html"
                Start-Process -FilePath gpresult -ArgumentList "/h", "`"$gpoDetailsFile`"", "/f" -NoNewWindow -Wait
                if (Test-Path $gpoDetailsFile) {
                    $out += "`nDetaillierter GPO-Bericht wurde erstellt unter: $gpoDetailsFile"
                }
                
            } catch {
                $out += "Fehler beim Abrufen des GPO-Status: $_"
            }
            
            # 3. Kerberos und Authentifizierungsstatusinformationen
            $out += "`n--- Kerberos & Authentifizierung ---"
            
            # Kerberos-Tickets abrufen
            try {
                $tickets = klist 2>&1
                if ($tickets -notmatch "Es wurden keine Anmeldeinformationen gefunden" -and 
                    $tickets -notmatch "No credentials" -and
                    $tickets -notmatch "failed") {
                    
                    $validTicket = $tickets -match "krbtgt"
                    $ticketStatus = if ($validTicket) { 'OK' } else { 'WARN' }
                    $out += Write-Status "Gültiges Kerberos-Ticket: $($validTicket -ne $null)" $ticketStatus
                    
                    # Anzahl der Tickets
                    $ticketCount = ($tickets | Where-Object { $_ -match "Valid starting" }).Count
                    $out += "Anzahl Kerberos-Tickets: $ticketCount"
                } else {
                    $out += Write-Status "Keine Kerberos-Tickets gefunden" 'WARN'
                }
            } catch {
                $out += "Fehler beim Abrufen der Kerberos-Tickets: $_"
            }
            
            # LDAP-Bindung überprüfen
            try {
                $domain = $computerSystem.Domain
                $ldapPath = "LDAP://$domain"
                $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
                
                if ($directoryEntry.Name -ne $null) {
                    $out += Write-Status "LDAP-Bindung zur Domäne erfolgreich" 'OK'
                } else {
                    $out += Write-Status "LDAP-Bindung zur Domäne fehlgeschlagen" 'CRIT'
                }
            } catch {
                $out += Write-Status "LDAP-Bindungsfehler: $_" 'CRIT'
            }
            
        } else {
            $out += Write-Status "Computer ist NICHT Teil einer Domäne. Arbeitsgruppe: $($computerSystem.Workgroup)" 'WARN'
        }
    }
    catch {
        $out += "Fehler beim Abrufen der Domäneninformationen: $_"
    }
    
    # Hilfsfunktion für die Domänenrolle
    function Get-DomänenrolleText {
        param([int]$roleValue)
        
        switch ($roleValue) {
            0 { "Eigenständige Arbeitsstation" }
            1 { "Mitglied einer Arbeitsgruppe" }
            2 { "Domänenmitglied" }
            3 { "Domänencontroller" }
            4 { "Backup-Domänencontroller" }
            5 { "Primärer Domänencontroller" }
            default { "Unbekannt ($roleValue)" }
        }
    }
    
    $out -join "`n"
}

#endregion

#region CRITICAL POINTS SUMMARY
# Sammeln der kritischen Punkte
$CriticalPoints = @()

# Prüfe alle gesammelten Daten auf kritische Punkte
foreach ($key in $SystemData.Keys) {
    $content = $SystemData[$key]
    
    # Suche nach Warnungen und kritischen Zuständen
    if ($content -match "🔴|🟡") {
        # Extrahiere Zeilen mit Warnungen
        $foundAlerts = [regex]::Matches($content, "(🔴|🟡).*?(\r?\n|$)")
        foreach ($alert in $foundAlerts) {
            $CriticalPoints += "$key`: $($alert.Value.Trim())"
        }
    }
}

# Erstelle die Zusammenfassung für den Bericht
$SystemData.CriticalSummary = if ($CriticalPoints.Count -gt 0) {
    "⚠️ ZUSAMMENFASSUNG KRITISCHER PUNKTE`n`n" + ($CriticalPoints -join "`n")
} else {
    "✅ SYSTEMSTATUS: Keine kritischen Punkte gefunden"
}
#endregion

#endregion
#region REPORT GENERATION
# Bericht zusammenstellen
$Report = @()
$Report += "===================================="
$Report += "📋 SYSTEMBERICHT $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
$Report += "===================================="
$Report += "🔑 Ausgeführt als: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
$Report += "🖥  Computername: $env:COMPUTERNAME" 
$Report += "👤 Admin-Rechte: $isAdmin"
$Report += "===================================="
$Report += "📊 ZUSAMMENFASSUNG:"
$Report += ""
$Report += $SystemData.CriticalSummary
$Report += ""

# Definierte Reihenfolge der Abschnitte
$orderedSections = @(
    # 1. System-Basisinformationen
    'SystemInfo',
    'ActiveDirectoryInfo',
    'WindowsUpdates',
    
    # 2. Hardware
    'HardwareDetails',
    'PerformanceInfo',
    
    # 3. Speicher
    'DiskHealth',
    'DiskUsage',
    'BitLockerStatus',
    
    # 4. Netzwerk
    'NetworkTest',
    'NetworkAdapters',
    'NetworkConnections',
    
    # 5. Software & Dienste
    'InstalledSoftware',
    'Services',
    'StartupItems',
    
    # 6. Sicherheit
    'DefenderStatus',
    'SecurityLog',
    
    # 7. Ressourcennutzung
    'TopProcesses',
    
    # 8. Probleme & Ereignisse
    'SystemEvents'
)

# Abschnitte in definierter Reihenfolge hinzufügen
foreach ($section in $orderedSections) {
    if ($SystemData.ContainsKey($section)) {
        $Report += "===================================="
        $Report += "📂 " + $section + ":"
        
        # Kategorie-Icons für bessere Übersicht
        $categoryIcon = switch ($section) {
            'SystemInfo'         { "🖥️ SYSTEM" }
            'ActiveDirectoryInfo' { "🌐 ACTIVE DIRECTORY" }
            'WindowsUpdates'     { "🔄 UPDATES" }
            'HardwareDetails'    { "🔧 HARDWARE" }
            'PerformanceInfo'    { "⚡ LEISTUNG" }
            'DiskHealth'         { "💽 SPEICHER" }
            'DiskUsage'          { "💾 SPEICHERNUTZUNG" }
            'BitLockerStatus'    { "🔐 VERSCHLÜSSELUNG" }
            'NetworkTest'        { "🌐 NETZWERK" }
            'NetworkAdapters'    { "📡 NETZWERKADAPTER" }
            'NetworkConnections' { "🔌 NETZWERKVERBINDUNGEN" }
            'InstalledSoftware'  { "📦 SOFTWARE" }
            'Services'           { "⚙️ DIENSTE" }
            'StartupItems'       { "🚀 AUTOSTART" }
            'DefenderStatus'     { "🛡️ SICHERHEIT" }
            'SecurityLog'        { "🔒 SICHERHEITSLOG" }
            'TopProcesses'       { "📊 PROZESSE" }
            'SystemEvents'       { "⚠️ EREIGNISSE" }
            default              { "" }
        }
        
        if ($categoryIcon) {
            $Report += $categoryIcon
        }
        
        $Report += ""
        $Report += $SystemData[$section]
    }
}

# Speichern
$Report | Out-File -FilePath $OutputPath -Encoding $Encoding -Force
Write-Host "✅ Vollständiger Bericht gespeichert unter: $OutputPath" -ForegroundColor Green
#endregion