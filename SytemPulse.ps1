#Requires -Version 5.1

<#
.SYNOPSIS
    Umfassender Windows-Systemdiagnosebericht mit Gesundheitscheck und Problemidentifikation

.DESCRIPTION
    Erstellt einen umfassenden Systemdiagnosebericht für Windows-Systeme mit automatischer
    Problemerkennung und visuellen Statusanzeigen (🟢🟡🔴). Erfasst detaillierte Informationen zu:
    
    - System: OS, BIOS, Uptime, Windows-Updates
    - Active Directory: Domänenstatus, GPO, Kerberos-Tickets, LDAP-Konnektivität 
    - Hardware: CPU, RAM, Grafikkarten, Performance-Daten
    - Speicher: Festplatten, SMART-Status, Speichernutzung, BitLocker
    - Netzwerk: Adapter, Verbindungen, Konnektivität, offene Ports
    - Software: Installierte Programme, Dienste, Autostart-Einträge
    - Sicherheit: Windows Defender, Firewall, Bedrohungen, fehlgeschlagene Anmeldungen
    - Ereignisse: Kritische Systemfehler und Warnungen
    
    Der Bericht beginnt mit einer Zusammenfassung aller kritischen Punkte für schnelle Problemidentifikation
    und kann durch einen Dateiauswahl-Dialog an beliebigen Orten gespeichert werden.

.NOTES
    Author:        Yasin Aslan
    Version:       1.1
    LastModified:  2025-08-15
    Requires:      PowerShell 5.1 oder höher, Administratorrechte
    OS Support:    Windows 10/11, Windows Server 2016+
    # Copyright (c) 2025 Yasin Aslan
    # MIT License - https://opensource.org/licenses/MIT

.EXAMPLE
    .\SystemPulse.ps1
    Führt das Skript aus und erstellt einen vollständigen Bericht auf dem Desktop

.OUTPUTS
    Eine formatierte Textdatei (Systembericht_FULL.txt) auf dem Desktop des Benutzers
    mit chronologisch angeordneten Systemdiagnosedaten.
    
.LINK
    https://github.com/aslan-y/SystemPulse
#>

#region SETUP & PREREQUISITES
# Admin-Check
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) { 
    Write-Error "❌ Dieses Skript muss mit Adminrechten ausgeführt werden!" 
    exit 1
}

# PowerShell-Umgebung optimieren
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"  # Beschleunigt Operationen durch Verstecken von Fortschrittsbalken

# Importieren des notwendigen Namespace für Runspaces
Add-Type -AssemblyName System.Management.Automation

# Jobs-Throttling für parallele Verarbeitung
$maxJobs = 4  # Maximale Anzahl gleichzeitiger Jobs
$runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $maxJobs)
$runspacePool.Open()

# Ermitteln des ausführenden und angemeldeten Benutzers
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentUser = $currentIdentity.Name
$elevatedContext = $isAdmin -and $currentUser -match "\\[^\\]+$" -and $currentUser -notmatch [regex]::Escape("SYSTEM")

# Ermitteln des tatsächlich am System angemeldeten Benutzers (falls Script als Admin ausgeführt wird)
$actualLoggedInUser = $null
try {
    # Alternative 1: Über Registry LastLoggedOnUser (zuverlässigster Weg)
    $lastUser = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Name LastLoggedOnUser -ErrorAction SilentlyContinue
    if ($lastUser -and $lastUser.LastLoggedOnUser) {
        $actualLoggedInUser = $lastUser.LastLoggedOnUser
        Write-Host "Ermittelter angemeldeter Benutzer (Registry): $actualLoggedInUser" -ForegroundColor Cyan
    }
    
    # Alternative 2: Über Abfrage der aktiven Explorer-Prozesse (wenn Registry nicht funktioniert)
    if (-not $actualLoggedInUser) {
        $explorerProcesses = Get-Process -Name explorer -IncludeUserName -ErrorAction SilentlyContinue | 
                             Where-Object { $_.UserName -and $_.UserName -ne "" } | 
                             Select-Object -First 1 -ExpandProperty UserName
        if ($explorerProcesses) {
            $actualLoggedInUser = $explorerProcesses
            Write-Host "Ermittelter angemeldeter Benutzer (Explorer): $actualLoggedInUser" -ForegroundColor Cyan
        }
    }
    
    # Alternative 3: QUERY USER-Befehl (als Fallback)
    if (-not $actualLoggedInUser) {
        $queryUser = query user 2>&1
        if ($queryUser -notmatch "No User exists") {
            $activeSession = $queryUser | Select-Object -Skip 1 | Where-Object {$_ -match "Active"} | Select-Object -First 1
            if ($activeSession -match '(\S+)\s+.*') {
                $username = $Matches[1]
                $domain = $env:USERDOMAIN
                $actualLoggedInUser = "$domain\$username"
                Write-Host "Ermittelter angemeldeter Benutzer (Query): $actualLoggedInUser" -ForegroundColor Cyan
            }
        }
    }
    
    # Fallback auf WMI (wird jetzt als letzte Option verwendet)
    if (-not $actualLoggedInUser) {
        $loggedInUsers = Get-WmiObject Win32_LoggedOnUser -ErrorAction SilentlyContinue | 
                         Where-Object { $_.Antecedent -match 'Domain="([^"]+)",Name="([^"]+)"' } |
                         ForEach-Object { 
                             $domain = $Matches[1]
                             $username = $Matches[2]
                             if ($domain -ne "NT AUTHORITY" -and $domain -ne "Window Manager" -and 
                                 $domain -ne "DWM-1" -and $domain -ne "Font Driver Host") {
                                 "$domain\$username"
                             }
                         } | Select-Object -Unique
                             
        if ($loggedInUsers -and $loggedInUsers.Count -gt 0) {
            # Bevorzuge Domänenbenutzer gegenüber lokalen Benutzern
            $domainUsers = $loggedInUsers | Where-Object { $_ -notmatch "^$env:COMPUTERNAME\\" }
            if ($domainUsers -and $domainUsers.Count -gt 0) {
                $actualLoggedInUser = $domainUsers[0]
                Write-Host "Ermittelter angemeldeter Benutzer (WMI): $actualLoggedInUser" -ForegroundColor Cyan
            } else {
                $actualLoggedInUser = $loggedInUsers[0]
                Write-Host "Ermittelter angemeldeter Benutzer (WMI): $actualLoggedInUser" -ForegroundColor Cyan
            }
        }
    }
    
    # Ansatz 2: Über die Registry (Letzter angemeldeter Benutzer)
    if (-not $actualLoggedInUser) {
        $lastUser = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Name LastLoggedOnUser -ErrorAction SilentlyContinue
        if ($lastUser) {
            $actualLoggedInUser = $lastUser.LastLoggedOnUser
            Write-Host "Ermittelter angemeldeter Benutzer (Registry-Fallback): $actualLoggedInUser" -ForegroundColor Cyan
        }
    }
} catch {
    Write-Warning "Fehler bei der Benutzerermittlung: $_"
}

# Melde den erkannten Benutzer im Protokoll
if ($actualLoggedInUser) {
    Write-Host "Ausführender Benutzer: $currentUser, Angemeldeter Benutzer: $actualLoggedInUser" -ForegroundColor Green
} else {
    Write-Host "Kein separater angemeldeter Benutzer erkannt. Verwende: $currentUser" -ForegroundColor Yellow
    $actualLoggedInUser = $currentUser
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
        [scriptblock]$ScriptBlock,
        [switch]$RunParallel
    )
    
    if ($RunParallel) {
        # Parallele Ausführung via Runspace
        try {
            $powershell = [powershell]::Create().AddScript($ScriptBlock)
            $powershell.RunspacePool = $runspacePool
            
            return [PSCustomObject]@{
                Name = $Command
                Powershell = $powershell
                Handle = $powershell.BeginInvoke()
            }
        } catch {
            Write-Warning "❌ Fehler beim Starten des parallelen Tasks '$Command': $_"
            return $null
        }
    }
    else {
        try { 
            Write-Progress -Activity "Sammle Systeminformationen" -Status $Command
            & $ScriptBlock 
        }
        catch { 
            Write-Warning "❌ Fehler bei '$Command': $_"
            return "❌ Fehler bei '$Command'" 
        }
    }
}

# Hilfsfunktion zum Sammeln der Ergebnisse aus parallelen Jobs
function Get-ParallelResults {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Jobs
    )
    
    $results = @{}
    
    foreach ($job in $Jobs) {
        try {
            $result = $job.Powershell.EndInvoke($job.Handle)
            $results[$job.Name] = $result
        }
        catch {
            $results[$job.Name] = "❌ Fehler bei paralleler Ausführung: $_"
        }
        finally {
            $job.Powershell.Dispose()
        }
    }
    
    return $results
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

# Parallele Datensammlung für zeitintensive Abfragen
$parallelJobs = @()

# Starte parallele Aufgaben für zeitintensive Abfragen
$parallelJobs = @()

# SystemEvents-Task
$scriptBlock1 = {
    $out = @()
    $out += "⚠️ Kritische Ereignisse der letzten 7 Tage:"
    
    try {
        $lastWeek = (Get-Date).AddDays(-7)
        $criticalEvents = Get-WinEvent -FilterHashtable @{
            LogName   = @('System', 'Application')
            Level     = 1, 2  # Error oder Critical
            StartTime = $lastWeek
        } -MaxEvents 50 -ErrorAction SilentlyContinue
        
        if ($criticalEvents.Count -gt 0) {
            foreach ($evt in $criticalEvents) {
                $timeStr = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm")
                $levelSymbol = if ($evt.Level -eq 1) { "🔴" } else { "🟠" }
                $out += "$levelSymbol [$timeStr] $($evt.ProviderName): $($evt.Message.Split("`n")[0])"
            }
        } else {
            $out += "🟢 Keine kritischen Ereignisse in den letzten 7 Tagen gefunden"
        }
    } catch {
        $out += "🟡 Fehler beim Lesen der Ereignisprotokolle: $_"
    }
    
    return $out
}
$parallelJobs += Get-SystemData -Command "SystemEvents" -ScriptBlock $scriptBlock1 -RunParallel

# InstalledSoftware-Task
$scriptBlock2 = {
    $out = @()
    $out += "📦 Installierte Software:"
    
    try {
        $software = @()
        # 64-bit Software
        $software += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                    Where-Object { $_.DisplayName -ne $null } |
                    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        
        # 32-bit Software auf 64-bit System
        if (Test-Path 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\') {
            $software += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
                        Where-Object { $_.DisplayName -ne $null } |
                        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        }
        
        # Top 15 Programme nach Installationsdatum sortiert
        $software = $software | Sort-Object InstallDate -Descending | Select-Object -First 15
        
        foreach ($app in $software) {
            $out += "  - $($app.DisplayName) v$($app.DisplayVersion) von $($app.Publisher)"
        }
        
        $out += "  [...]"
        $out += "  Insgesamt installierte Programme: $($software.Count)"
    } catch {
        $out += "🟡 Fehler beim Auflisten der installierten Software: $_"
    }
    
    return $out
}
$parallelJobs += Get-SystemData -Command "InstalledSoftware" -ScriptBlock $scriptBlock2 -RunParallel

# WindowsUpdates-Task
$scriptBlock3 = {
    $out = @()
    $out += "🔄 Windows Update-Status:"
    
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        
        # Letzte Prüfung
        $lastCheck = $searcher.GetTotalHistoryCount()
        if ($lastCheck -gt 0) {
            $lastUpdate = $searcher.QueryHistory(0, 1) | Select-Object -First 1
            $out += "  Letztes Update: $($lastUpdate.Title) ($($lastUpdate.Date))"
            
            # Ausstehende Updates
            $pendingUpdates = $searcher.Search("IsInstalled=0 and IsHidden=0").Updates
            if ($pendingUpdates.Count -gt 0) {
                $out += "🟡 $($pendingUpdates.Count) ausstehende Updates gefunden!"
                $pendingUpdates | Select-Object -First 5 | ForEach-Object {
                    $out += "  - $($_.Title)"
                }
                if ($pendingUpdates.Count -gt 5) {
                    $out += "  - [...und $($pendingUpdates.Count - 5) weitere]"
                }
            } else {
                $out += "🟢 System ist auf dem neuesten Stand"
            }
        } else {
            $out += "🟡 Keine Update-Historie gefunden"
        }
    } catch {
        $out += "🟡 Fehler beim Prüfen der Windows Updates: $_"
    }
    
    return $out
}
$parallelJobs += Get-SystemData -Command "WindowsUpdates" -ScriptBlock $scriptBlock3 -RunParallel

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
    
    #region 1. Check Domain Membership
    try {
        $computerSystem = Get-WmiObject Win32_ComputerSystem
        $isInDomain = $computerSystem.PartOfDomain
        $domain = $computerSystem.Domain
        
        # Domain status and role
        if ($isInDomain) {
            $out += Write-Status "Computer ist Mitglied der Domäne: $domain" 'OK'
            
            # Determine domain role
            $roleText = switch ($computerSystem.DomainRole) {
                0 { "Eigenständige Arbeitsstation" }
                1 { "Mitglied einer Arbeitsgruppe" }
                2 { "Domänenmitglied" }
                3 { "Domänencontroller" }
                4 { "Backup-Domänencontroller" }
                5 { "Primärer Domänencontroller" }
                default { "Unbekannt ($($computerSystem.DomainRole))" }
            }
            $out += "Domänenrolle: $($computerSystem.DomainRole) - $roleText"
            
            # Check for contradiction between PartOfDomain and DomainRole
            if ($computerSystem.DomainRole -lt 2) {
                $out += Write-Status "Widerspruch: Computer meldet Domänenmitgliedschaft, aber Rolle ist: $roleText" 'WARN'
                
                # Check user context
                $scriptUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                $isDomainScriptUser = $scriptUser -match [regex]::Escape($domain)
                
                if ($elevatedContext -and $actualLoggedInUser -and $scriptUser -ne $actualLoggedInUser) {
                    # Script running with admin rights but as different user
                    $isDomainActualUser = $actualLoggedInUser -match [regex]::Escape($domain)
                    
                    if ($isDomainActualUser) {
                        $out += Write-Status "Skript wird als Administrator ausgeführt, aber ein Domänenbenutzer ist angemeldet" 'WARN'
                        $out += "Angemeldet: $actualLoggedInUser | Skript läuft als: $scriptUser"
                    } 
                    elseif (!$isDomainScriptUser) {
                        $out += Write-Status "Lokaler Benutzer statt Domänenbenutzer" 'WARN'
                        $out += "Bitte als Domänenbenutzer anmelden für volle Funktionalität"
                    }
                } 
                elseif (!$isDomainScriptUser) {
                    $out += Write-Status "Lokaler Benutzer statt Domänenbenutzer" 'WARN'
                    $out += "Bitte als Domänenbenutzer anmelden für volle Funktionalität"
                }
            } else {
                $out += "Domänenrolle: $($computerSystem.DomainRole) - $roleText"
            }
            #endregion
            
            #region 2. Domain Function Level and Infrastructure
            try {
                # Check if AD module is available
                if (Get-Module -ListAvailable -Name ActiveDirectory) {
                    # Improved error handling when importing module
                    try {
                        Import-Module ActiveDirectory -ErrorAction Stop
                    }
                    catch {
                        $out += "Warnung: ActiveDirectory-Modul konnte nicht geladen werden: $_"
                    }
                    
                    # Improved error handling for AD queries
                    try {
                        $domainInfo = Get-ADDomain -ErrorAction Stop
                        if ($domainInfo) {
                            $out += "`n--- Domänen-Informationen ---"
                            $out += "Domänenname (NetBIOS): $($domainInfo.NetBIOSName)"
                            $out += "Domänenname (DNS): $($domainInfo.DNSRoot)"
                            $out += "Funktionsebene: $($domainInfo.DomainMode)"
                            $out += "PDC-Emulator: $($domainInfo.PDCEmulator)"
                            
                            # Domain Controller reachability
                            $dcTest = Test-Connection -ComputerName $domainInfo.PDCEmulator -Count 1 -Quiet -ErrorAction SilentlyContinue
                            $dcStatus = if ($dcTest) { 'OK' } else { 'CRIT' }
                            $out += Write-Status "PDC-Erreichbarkeit: $dcTest" $dcStatus
                        }
                    }
                    catch {
                        $out += "Fehler bei AD-Domänenabfrage: $_"
                        
                        # Alternative method with WMI
                        try {
                            $domain = $computerSystem.Domain
                            $out += "`n--- Domänen-Informationen (alternative Methode) ---"
                            $out += "Domänenname: $domain"
                            
                            # Ping test to domain name
                            $domainPing = Test-Connection -ComputerName $domain -Count 1 -Quiet -ErrorAction SilentlyContinue
                            $domainStatus = if ($domainPing) { 'OK' } else { 'WARN' }
                            $out += Write-Status "Domäne erreichbar: $domainPing" $domainStatus
                            
                            # Check for typical AD services
                            $out += "`n--- Domänendienst-Erreichbarkeit ---"
                            
                            # Check DNS SRV entries for AD
                            try {
                                $dcRecords = Resolve-DnsName -Name "_ldap._tcp.$domain" -Type SRV -ErrorAction Stop
                                if ($dcRecords) {
                                    $out += Write-Status "DNS-SRV-Einträge für Domänencontroller gefunden" 'OK'
                                    $out += "Gefundene Domänencontroller:"
                                    
                                    # Only use valid DC records with names
                                    $validDCs = $dcRecords | Where-Object { $_.NameTarget -and -not [string]::IsNullOrWhiteSpace($_.NameTarget) }
                                    
                                    if ($validDCs.Count -gt 0) {
                                        foreach ($dc in $validDCs) {
                                            $out += "  - $($dc.NameTarget) (Priorität: $($dc.Priority))"
                                            
                                            # Additional test for typical AD ports
                                            try {
                                                $portTest = Test-NetConnection -ComputerName $dc.NameTarget -Port 389 -WarningAction SilentlyContinue -ErrorAction Stop
                                                $ldapStatus = if ($portTest.TcpTestSucceeded) { 'OK' } else { 'WARN' }
                                                $out += Write-Status "    LDAP-Port (389) erreichbar: $($portTest.TcpTestSucceeded)" $ldapStatus
                                            } catch {
                                                $out += "    LDAP-Port-Test fehlgeschlagen: $_"
                                            }
                                        }
                                    } else {
                                        $out += Write-Status "  Keine gültigen Domänencontroller-Einträge gefunden" 'WARN'
                                    }
                                }
                            } catch {
                                $out += Write-Status "Keine DNS-SRV-Einträge für Domänencontroller gefunden: $_" 'WARN'
                            }
                        }
                        catch {
                            $out += "Alternative Methode zur Domänenprüfung fehlgeschlagen: $_"
                        }
                    }
                    
                    # Computer account details
                    try {
                        $computerObj = Get-ADComputer $env:COMPUTERNAME -Properties * -ErrorAction SilentlyContinue
                        if ($computerObj) {
                            $out += "`n--- Computer-Kontoinformationen ---"
                            $out += "Erstellungsdatum: $($computerObj.Created)"
                            $out += "Letzte Kennwortänderung: $($computerObj.PasswordLastSet)"
                            
                            # Check computer account status
                            $accountStatus = if ($computerObj.Enabled) { 'OK' } else { 'CRIT' }
                            $out += Write-Status "Konto aktiv: $($computerObj.Enabled)" $accountStatus
                            
                            # Last logon/contact
                            $lastLogon = if ($computerObj.LastLogonDate) { $computerObj.LastLogonDate } else { "Nie" }
                            $out += "Letzte Anmeldung: $lastLogon"
                        }
                    } catch {
                        $out += "Fehler beim Abrufen der Computer-Kontoinformationen: $_"
                    }
                    
                    # Domain trusts
                    try {
                        $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
                        if ($trusts) {
                            $out += "`n--- Domänen-Vertrauensstellungen ---"
                            foreach ($trust in $trusts) {
                                $out += "Vertrauensstellung zu: $($trust.Name) (Typ: $($trust.TrustType), Richtung: $($trust.TrustDirection))"
                            }
                        }
                    } catch {
                        # Ignore if no trusts found
                    }
                } else {
                    $out += "`nHinweis: Das ActiveDirectory-Modul ist nicht installiert. Erweiterte AD-Informationen sind nicht verfügbar."
                }
            }
            catch {
                $out += "Fehler beim Abrufen von AD-Informationen: $_"
            }
            #endregion
            
            #region 3. Group Policy Status
            $out += "`n--- Gruppenrichtlinien-Status ---"
            
            # GPO basic check with RSOP
            try {
                # GPO Last Refresh
                $gpoLastRefresh = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine" -Name RefreshTimeLast -ErrorAction SilentlyContinue
                if ($gpoLastRefresh) {
                    $lastRefreshTime = [DateTime]::FromFileTime($gpoLastRefresh.RefreshTimeLast)
                    $timeSinceRefresh = (Get-Date) - $lastRefreshTime
                    $refreshStatus = if ($timeSinceRefresh.TotalHours -gt 24) { 'WARN' } else { 'OK' }
                    $out += Write-Status "Letzte GPO-Aktualisierung: $($lastRefreshTime) (vor $([math]::Round($timeSinceRefresh.TotalHours, 1)) Stunden)" $refreshStatus
                }
                
                # GPResult output for important settings
                $gpResultOutput = & gpresult /r
                
                # Group error signatures for better overview
                $gpErrors = $gpResultOutput | Where-Object { 
                    $_ -match "Fehler" -or 
                    $_ -match "nicht angewendet" -or 
                    $_ -match "herausgefilterte" 
                }
                
                if ($gpErrors) {
                    # Filter out empty or unnecessary errors
                    $significantErrors = $gpErrors | Where-Object { 
                        -not [string]::IsNullOrWhiteSpace($_) -and 
                        $_ -notmatch "^\s+$" -and
                        $_ -notmatch "Filterung:\s+Nicht angewendet \(Leer\)$"
                    }
                    
                    if ($significantErrors.Count -gt 0) {
                        $out += Write-Status "Gruppenrichtlinien-Fehler gefunden:" 'WARN'
                        foreach ($gpError in $significantErrors) {
                            $out += "  - $gpError"
                        }
                    } else {
                        $out += "Keine signifikanten GPO-Fehler gefunden"
                    }
                }
                
                # Applied computer policies
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
                
                # Check security-relevant settings
                $out += "`n--- Sicherheitsrelevante GPO-Einstellungen ---"
                
                # Local Administrator group (via WMI)
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
                
                # Check password policy
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
                
                # Offline files (relevant for laptops)
                try {
                    $offlineFiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache" -Name Enabled -ErrorAction SilentlyContinue
                    if ($offlineFiles) {
                        $out += "Offlinefiles Status: " + $(if ($offlineFiles.Enabled -eq 1) { "Aktiviert" } else { "Deaktiviert" })
                    }
                } 
                catch {
                    # Ignore if not present
                }
            
                # Generate detailed GPO output
                $gpoDetailsFile = "$env:TEMP\GPODetails.html"
                Start-Process -FilePath gpresult -ArgumentList "/h", "`"$gpoDetailsFile`"", "/f" -NoNewWindow -Wait
                if (Test-Path $gpoDetailsFile) {
                    $out += "`nDetaillierter GPO-Bericht wurde erstellt unter: $gpoDetailsFile"
                }
            }
            catch {
                $out += "Fehler beim Abrufen des GPO-Status: $_"
            }
            #endregion
            
            #region 4. Kerberos and Authentication Status
            $out += "`n--- Kerberos & Authentifizierung ---"
            
            # Get Kerberos tickets
            try {
                $tickets = klist 2>&1
                if ($tickets -notmatch "Es wurden keine Anmeldeinformationen gefunden" -and 
                    $tickets -notmatch "No credentials" -and
                    $tickets -notmatch "failed") {
                    
                    # Enhanced detection of valid tickets
                    $validTicket = $tickets -match "krbtgt"
                    if ($validTicket) {
                        $ticketStatus = 'OK'
                        $out += Write-Status "Gültiges Kerberos-Ticket vorhanden" $ticketStatus
                    } else {
                        $ticketStatus = 'WARN'
                        $out += Write-Status "Kein Kerberos-TGT-Ticket gefunden" $ticketStatus
                    }
                    
                    # Ticket count
                    $ticketCount = ($tickets | Where-Object { $_ -match "Valid starting" -or $_ -match "Gültig ab" }).Count
                    $out += "Anzahl Kerberos-Tickets: $ticketCount"
                } else {
                    $out += Write-Status "Keine Kerberos-Tickets gefunden" 'WARN'
                    
                    # Show diagnostics and tips
                    $out += "`nDiagnose für fehlende Kerberos-Tickets:"
                    
                    # Check if kinit is available (if Kerberos client is installed)
                    try {
                        $kinitTest = Get-Command kinit -ErrorAction SilentlyContinue
                        if ($kinitTest) {
                            $out += "  - Kerberos-Client ist installiert"
                        }
                    } catch {
                        # Ignore if not available
                    }
                    
                    # Check Secure Channel
                    try {
                        $nltest = nltest /sc_query:$($computerSystem.Domain) 2>&1
                        if ($nltest -match "NERR_Success") {
                            $out += "  - Secure Channel zur Domäne ist aktiv"
                        } else {
                            $out += "  - Problem mit Secure Channel zur Domäne festgestellt"
                            $out += "    Empfehlung: nltest /sc_reset:$($computerSystem.Domain) ausführen"
                        }
                    } catch {
                        # Ignore if nltest not available
                    }
                    
                    # Recommend ticket renewal
                    $out += "  - Empfehlung zur Ticketaktualisierung:"
                    $out += "    1. Abmelden und wieder anmelden"
                    $out += "    2. Kennwort-Aktualisierung durchführen"
                    $out += "    3. Zeitdifferenz zwischen Client und DC prüfen"
                    $out += "    4. Verwenden Sie 'klist purge' um den Ticketspeicher zu leeren"
                }
            } catch {
                $out += "Fehler beim Abrufen der Kerberos-Tickets: $_"
                
                # Alternative method for Kerberos status
                try {
                    $nltest = nltest /sc_query:$($computerSystem.Domain) 2>&1
                    if ($nltest -match "NERR_Success") {
                        $out += Write-Status "Secure Channel zur Domäne aktiv (nltest)" 'OK'
                    } else {
                        $out += Write-Status "Secure Channel zur Domäne hat Probleme (nltest)" 'WARN'
                    }
                } catch {
                    # Ignore if nltest not available
                }
            }
            #endregion
            
            #region 5. LDAP Binding Check
            try {
                $domain = $computerSystem.Domain
                $ldapPath = "LDAP://$domain"
                $ldapSuccess = $false
                $methodUsed = ""
                
                # Method 1: Standard DirectoryEntry with current credentials
                try {
                    $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
                    if ($directoryEntry.Name -ne $null) {
                        $ldapSuccess = $true
                        $methodUsed = "Standard DirectoryEntry"
                    }
                } catch {
                    # Log error and continue with alternative methods
                    $method1Error = $_
                }
                
                # Method 2: System.DirectoryServices.Protocols if Method 1 fails
                if (-not $ldapSuccess) {
                    try {
                        Add-Type -AssemblyName System.DirectoryServices.Protocols
                        $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($domain)
                        $conn.Bind()
                        $ldapSuccess = $true
                        $methodUsed = "DirectoryServices.Protocols"
                    } catch {
                        # Log error and continue with alternative methods
                        $method2Error = $_
                    }
                }
                
                # Method 3: ADSI provider with port 389 (standard) or 636 (SSL)
                if (-not $ldapSuccess) {
                    try {
                        # Try with standard LDAP port 389
                        $rootDSE = [ADSI]"LDAP://$domain:389/RootDSE"
                        $rootDSE.RefreshCache()
                        if ($rootDSE.Properties["defaultNamingContext"]) {
                            $ldapSuccess = $true
                            $methodUsed = "ADSI Provider (Port 389)"
                        }
                    } catch {
                        # Try with LDAP-SSL port 636
                        try {
                            $rootDSE = [ADSI]"LDAP://$domain:636/RootDSE"
                            $rootDSE.RefreshCache()
                            if ($rootDSE.Properties["defaultNamingContext"]) {
                                $ldapSuccess = $true
                                $methodUsed = "ADSI Provider (Port 636 - SSL)"
                            }
                        } catch {
                            # All ADSI attempts failed
                            $method3Error = $_
                        }
                    }
                }
                
                # Method 4: Global Catalog attempt via port 3268
                if (-not $ldapSuccess) {
                    try {
                        $gc = [ADSI]"GC://$domain:3268"
                        $gc.RefreshCache()
                        if ($gc.Name -ne $null) {
                            $ldapSuccess = $true
                            $methodUsed = "Global Catalog (Port 3268)"
                        }
                    } catch {
                        # Global Catalog not available
                        $method4Error = $_
                    }
                }
                
                if ($ldapSuccess) {
                    $out += Write-Status "LDAP-Bindung zur Domäne erfolgreich ($methodUsed)" 'OK'
                } else {
                    # Fallback: DNS test to domain controller
                    $dcTest = Test-Connection -ComputerName $domain -Count 1 -Quiet -ErrorAction SilentlyContinue
                    if ($dcTest) {
                        $out += Write-Status "LDAP-Bindung fehlgeschlagen, aber DC erreichbar via Ping" 'WARN'
                        $out += "`nDomänen-Authentifizierungsdiagnose:"
                        
                        # Test network reachability
                        $out += "  1. Netzwerk-Konnektivität zum DC: Vorhanden"
                        
                        # Extended diagnostics: Show error details
                        $out += "`n  - LDAP-Fehlerdetails:"
                        if ($method1Error) { $out += "    • Methode 1 (DirectoryEntry): $($method1Error.Message)" }
                        if ($method2Error) { $out += "    • Methode 2 (DirectoryServices.Protocols): $($method2Error.Message)" }
                        if ($method3Error) { $out += "    • Methode 3 (ADSI Provider): $($method3Error.Message)" }
                        if ($method4Error) { $out += "    • Methode 4 (Global Catalog): $($method4Error.Message)" }
                        
                        #region 6. Extended Domain Diagnostics
                        try {
                            $computerNetBIOS = $env:COMPUTERNAME
                            $dnsServer = (Get-DnsClientServerAddress -AddressFamily IPv4 | 
                                          Where-Object {$_.ServerAddresses -ne $null} | 
                                          Select-Object -First 1).ServerAddresses[0]
                            
                            # Test DNS resolution
                            $dnsTest = Resolve-DnsName -Name $domain -Server $dnsServer -Type A -ErrorAction SilentlyContinue
                            if ($dnsTest) {
                                $out += "  2. DNS-Auflösung für Domain: Erfolgreich"
                                # Additional DNS information
                                $out += "    • Domänencontroller-IPs:"
                                try {
                                    $dcIPs = Resolve-DnsName -Name $domain -Type A -ErrorAction SilentlyContinue | 
                                             Select-Object -ExpandProperty IPAddress
                                    foreach ($ip in $dcIPs) {
                                        $out += "      - $ip"
                                    }
                                } catch {
                                    $out += "      Keine DCs über DNS gefunden"
                                }
                            } else {
                                $out += "  2. DNS-Auflösung für Domain: Fehlgeschlagen - Mögliches DNS-Problem"
                                # Show DNS server information
                                $out += "    • DNS-Server: $dnsServer"
                                $out += "    • Alternativer Test mit nslookup:"
                                try {
                                    $nslookup = nslookup $domain 2>&1
                                    $out += "      " + ($nslookup -join "`n      ")
                                } catch {
                                    $out += "      Nslookup fehlgeschlagen"
                                }
                            }
                        } catch {
                            $out += "  Fehler bei DNS-Tests: $_"
                        }
                        
                        # Test time synchronization
                        try {
                            $timeServer = $domain
                            $w32tm = w32tm /stripchart /computer:$timeServer /samples:1 /dataonly 2>&1
                            if ($w32tm -match "Fehler|Error") {
                                $out += "  3. Zeitsynchronisation mit DC: Problem - Zeitabweichung könnte Kerberos beeinträchtigen"
                                
                                # Extended time synchronization diagnostics
                                $out += "    • Lokale Zeiteinstellungen:"
                                try {
                                    $timeInfo = w32tm /query /status 2>&1
                                    $out += "      Zeitquelle: " + (($timeInfo | Where-Object { $_ -match "Source:" }) -replace "Source:", "").Trim()
                                    $out += "      Letztes Sync: " + (($timeInfo | Where-Object { $_ -match "Last Sync Time:" }) -replace "Last Sync Time:", "").Trim()
                                    
                                    # Calculate current time difference
                                    try {
                                        $netTime = w32tm /monitor /computers:$timeServer 2>&1
                                        $timeDiff = ($netTime | Where-Object { $_ -match "Offset" }) -replace ".*Offset:\s+([-+]?\d+\.\d+)s.*", '$1'
                                        if ($timeDiff -match "^[-+]?\d+\.\d+$") {
                                            $out += "      Zeitdifferenz zum DC: $timeDiff Sekunden"
                                            # If more than 5 minutes (300 seconds) difference, Kerberos is at risk
                                            if ([Math]::Abs([double]$timeDiff) -gt 300) {
                                                $out += "      KRITISCH: Zeitunterschied > 5 Minuten - Kerberos funktioniert nicht!"
                                            }
                                        }
                                    } catch {
                                        $out += "      Zeitdifferenz konnte nicht ermittelt werden: $_"
                                    }
                                } catch {
                                    $out += "      Zeitsynchronisationsinformationen nicht verfügbar: $_"
                                }
                                
                                # Solution suggestion
                                $out += "    • Lösungsvorschlag: Führen Sie als Administrator aus:"
                                $out += "      net time \\$domain /set /yes"
                            } else {
                                $out += "  3. Zeitsynchronisation mit DC: Erfolgreich"
                                # Additional time synchronization details
                                try {
                                    $netTime = w32tm /monitor /computers:$timeServer 2>&1
                                    $timeDiff = ($netTime | Where-Object { $_ -match "Offset" }) -replace ".*Offset:\s+([-+]?\d+\.\d+)s.*", '$1'
                                    if ($timeDiff -match "^[-+]?\d+\.\d+$") {
                                        $out += "    • Zeitdifferenz zum DC: $timeDiff Sekunden"
                                    }
                                } catch {
                                    # Ignore if the time difference cannot be retrieved
                                }
                            }
                        } catch {
                            $out += "  Fehler bei der Zeitsynchronisationsprüfung: $_"
                        }
                        
                        # Check if the computer is reachable
                        try {
                            $nltest = nltest /server:$computerNetBIOS /query 2>&1
                            if ($nltest -match "NERR_Success") {
                                $out += "  4. Computer-Konto-Status: OK"
                            } else {
                                $out += "  4. Computer-Konto-Status: Mögliches Problem - Computerkonto prüfen"
                                # Details on computer account problem
                                $out += "    • Nltest-Ausgabe: " + ($nltest -join ", ")
                            }
                        } catch {
                            $out += "  4. Computer-Konto-Status: Konnte nicht geprüft werden"
                        }
                        
                        # Additional Kerberos diagnostic tests
                        $out += "  5. Kerberos-Ticketstatus:"
                        try {
                            $klist = klist 2>&1
                            $ticketCount = ($klist | Where-Object { $_ -match "^#\d+>" }).Count
                            
                            if ($ticketCount -gt 0) {
                                $out += "    • Gültige Kerberos-Tickets: $ticketCount"
                                $domainTickets = $klist | Where-Object { $_ -match "krbtgt|$domain" }
                                if ($domainTickets) {
                                    $out += "    • Domänen-Tickets vorhanden"
                                } else {
                                    $out += "    • Keine Domänen-Tickets gefunden"
                                }
                            } else {
                                $out += "    • Keine Kerberos-Tickets vorhanden"
                            }
                        } catch {
                            $out += "    • Kerberos-Ticket-Status konnte nicht abgerufen werden: $_"
                        }
                        #endregion
                        
                        #region 7. Diagnostic Tips for Domain Issues
                        $out += "`nDiagnose-Tipps bei Domänenproblemen:"
                        $out += "  - Domänenverbindung ist technisch möglich, aber es gibt Authentifizierungsprobleme"
                        $out += "  - Domäne: $domain (erreichbar, aber keine Authentifizierung möglich)"
                        $out += "  - Domänenrolle ist $($computerSystem.DomainRole) (sollte 2 oder höher sein)"
                        
                        # Concrete solution suggestions
                        $out += "`nLösungsvorschläge:"
                        $out += "  1. Computer-Konto zurücksetzen:"
                        $out += "     netdom.exe reset $env:COMPUTERNAME /domain:$domain /userd:[admin] /passwordd:[passwort]"
                        $out += "  2. Kerberos-Tickets löschen und neu anfordern:"
                        $out += "     klist purge"
                        $out += "     gpupdate /force"
                        $out += "  3. Prüfen Sie, ob der Computer aus der Domäne entfernt wurde:"
                        $out += "     nltest /sc_verify:$domain"
                        $out += "  4. Überprüfen Sie die Windows-Firewall auf blockierte Domänenkommunikation"
                        $out += "  5. Netzwerkadapter-Probleme ausschließen (deaktivieren/aktivieren)"
                        #endregion
                        
                        #region 8. System State Information
                        $out += "`nSystemzustand-Informationen:"
                        
                        # Current logged-in user
                        $scriptUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                        $out += "  - Skript ausgeführt als: $scriptUser"
                        
                        # Check for administrator context vs. logged-in user
                        if ($elevatedContext -and $actualLoggedInUser -and $scriptUser -ne $actualLoggedInUser) {
                            # Show full path (no truncation)
                            $out += "  - Angemeldeter Benutzer: $actualLoggedInUser"
                            
                            # Universal domain user detection - works with all AD domains
                            $isDomainActualUser = $false
                            $detectionMethod = ""
                            
                            # Method 1: Check with simple domain pattern (Domain\Username)
                            if ($actualLoggedInUser -match "^[^\\]+\\") {
                                $actualUserDomain = ($actualLoggedInUser -split "\\")[0]
                                # Check if the username contains a domain that is not the computer name
                                if ($actualUserDomain -ne $env:COMPUTERNAME) {
                                    $isDomainActualUser = $true
                                    $detectionMethod = "Domänenbenutzer erkannt: $actualUserDomain ist nicht lokaler Computer $env:COMPUTERNAME"
                                }
                            }
                            
                            # Method 2: If defined, check against the known domain
                            if (-not $isDomainActualUser -and $domain -and $actualLoggedInUser -match [regex]::Escape($domain)) {
                                $isDomainActualUser = $true
                                $detectionMethod = "Domänenbenutzer erkannt durch Domänenabgleich mit $domain"
                            }
                            
                            # Method 3: Direct Windows API query to check domain membership
                            if (-not $isDomainActualUser) {
                                try {
                                    $user = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
                                    if ($user.Identity.AuthenticationType -eq "Kerberos") {
                                        $isDomainActualUser = $true
                                        $detectionMethod = "Domänenbenutzer erkannt durch Kerberos-Authentifizierung"
                                    }
                                } catch {
                                    # If the query fails, continue with other methods
                                }
                            }
                            
                            # Method 4: Check via WMI
                            if (-not $isDomainActualUser) {
                                try {
                                    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
                                    if ($computerSystem.PartOfDomain) {
                                        # Computer is part of a domain - check if the user is in the domain
                                        $userParts = $actualLoggedInUser -split "\\"
                                        if ($userParts.Count -eq 2) {
                                            # Compare with the domain from the computer
                                            if ($userParts[0] -eq $computerSystem.Domain -or $userParts[0] -eq $computerSystem.Domain.Split(".")[0]) {
                                                $isDomainActualUser = $true
                                                $detectionMethod = "Domänenbenutzer erkannt durch Abgleich mit Computer-Domäne $($computerSystem.Domain)"
                                            }
                                        }
                                    }
                                } catch {
                                    # If the query fails, continue with other methods
                                }
                            }
                            
                            # Output detection method only if a domain user has been detected
                            if ($isDomainActualUser) {
                                $out += "    ($detectionMethod)"
                                $out += Write-Status "  - Hinweis: Das Skript läuft mit Adminrechten, aber ein Domänenbenutzer ist angemeldet" 'WARN'
                                $out += "    Die Domänenfunktionen sind für den angemeldeten Benutzer verfügbar, nicht für den Skriptkontext"
                            } else {
                                $out += Write-Status "  - Wichtig: Weder das Skript noch der angemeldete Benutzer ist ein Domänenbenutzer" 'WARN'
                            }
                        } else {
                            # Universal domain user detection also for the script user
                            $isDomainScriptUser = $false
                            
                            # Method 1: Check with simple domain pattern (Domain\Username)
                            if ($scriptUser -match "^[^\\]+\\") {
                                $scriptUserDomain = ($scriptUser -split "\\")[0]
                                # Check if the username contains a domain that is not the computer name
                                if ($scriptUserDomain -ne $env:COMPUTERNAME) {
                                    $isDomainScriptUser = $true
                                }
                            }
                            
                            # Method 2: If defined, check against the known domain
                            if (-not $isDomainScriptUser -and $domain -and $scriptUser -match [regex]::Escape($domain)) {
                                $isDomainScriptUser = $true
                            }
                            
                            # Method 3: Direct Windows API query to check domain membership
                            if (-not $isDomainScriptUser) {
                                try {
                                    $user = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
                                    if ($user.Identity.AuthenticationType -eq "Kerberos") {
                                        $isDomainScriptUser = $true
                                    }
                                } catch {
                                    # If the query fails, continue with other methods
                                }
                            }
                            
                            # Method 4: Check via WMI
                            if (-not $isDomainScriptUser) {
                                try {
                                    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
                                    if ($computerSystem.PartOfDomain) {
                                        # Computer is part of a domain - check if the user is in the domain
                                        $userParts = $scriptUser -split "\\"
                                        if ($userParts.Count -eq 2) {
                                            # Compare with the domain from the computer
                                            if ($userParts[0] -eq $computerSystem.Domain -or $userParts[0] -eq $computerSystem.Domain.Split(".")[0]) {
                                                $isDomainScriptUser = $true
                                            }
                                        }
                                    }
                                } catch {
                                    # If the query fails, continue with other methods
                                }
                            }
                            
                            if (!$isDomainScriptUser) {
                                $out += Write-Status "  - Wichtig: Sie sind als lokaler Benutzer angemeldet, nicht als Domänenbenutzer" 'WARN'
                            }
                        }
                        
                        # Check if last login was with domain account
                        $lastUser = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Name LastLoggedOnUser -ErrorAction SilentlyContinue
                        if ($lastUser) {
                            $out += "  - Letzter angemeldeter Benutzer: $($lastUser.LastLoggedOnUser)"
                            
                            $isDomainLastUser = $lastUser.LastLoggedOnUser -match [regex]::Escape($domain)
                            $isDomainScriptUser = $scriptUser -match [regex]::Escape($domain)
                            if ($isDomainLastUser -and !$isDomainScriptUser -and (!$actualLoggedInUser -or $actualLoggedInUser -ne $lastUser.LastLoggedOnUser)) {
                                $out += Write-Status "  - Letzter Benutzer war Domänenbenutzer, aktueller ist lokaler Benutzer" 'WARN'
                                $out += "    Dies erklärt die fehlende Domänen-Konnektivität"
                            }
                        }
                        
                        # Check if computer name has been changed
                        $computerNameHistory = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" -ErrorAction SilentlyContinue
                        $activeComputerName = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -ErrorAction SilentlyContinue
                        if ($computerNameHistory -and $activeComputerName -and 
                            $computerNameHistory.ComputerName -ne $activeComputerName.ComputerName) {
                            $out += "  - Warnung: Computer-Name wurde geändert (alt: $($computerNameHistory.ComputerName), neu: $($activeComputerName.ComputerName))"
                            $out += "  - Computername-Änderung erfordert möglicherweise Aktualisierung in AD"
                        }
                        
                        # Check Netlogon status
                        $netlogonService = Get-Service "Netlogon" -ErrorAction SilentlyContinue
                        if ($netlogonService) {
                            $out += "  - Netlogon-Dienst: $($netlogonService.Status)"
                        }
                        #endregion
                        
                        #region 9. Recommended Actions
                        $out += "`nEmpfohlene Maßnahmen zur Behebung:"
                        
                        # Specific recommendations based on detected problem
                        try {
                            $scriptUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                            $isDomainScriptUser = $scriptUser -match [regex]::Escape($domain)
                            
                            # Check admin context vs. logged-in user
                            if ($elevatedContext -and $actualLoggedInUser -and $scriptUser -ne $actualLoggedInUser) {
                                $isDomainActualUser = $actualLoggedInUser -match [regex]::Escape($domain)
                            
                                if ($isDomainActualUser) {
                                    $out += "  - Diese Warnungen betreffen nur den Admin-Skriptkontext ($scriptUser)"
                                    $out += "  - Der angemeldete Benutzer ($actualLoggedInUser) hat vollen Domänenzugriff"
                                    $out += "  - Keine Aktion erforderlich, dies ist ein normales Verhalten bei Admin-Ausführung"
                                    $out += "  - Führen Sie das Skript ohne Adminrechte aus, um die Domänenfunktionen zu nutzen"
                                    $out += "  - Oder führen Sie es mit einem Domänen-Administratorkonto aus"
                                } 
                                elseif (!$isDomainScriptUser) {
                                    $out += "  - Als Domänenbenutzer anmelden (statt als lokaler Benutzer)"
                                    $out += "  - Sobald Sie als Domänenbenutzer angemeldet sind, werden alle Domänenfunktionen verfügbar sein"
                                    $out += "  - Lokaler Benutzer '$scriptUser' hat keinen Zugriff auf Domänenressourcen"
                                    
                                    # Check if last user was a domain user
                                    $lastUser = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Name LastLoggedOnUser -ErrorAction SilentlyContinue
                                    if ($lastUser -and $lastUser.LastLoggedOnUser -match [regex]::Escape($domain)) {
                                        $out += "  - Melden Sie sich mit dem Domänenbenutzer '$($lastUser.LastLoggedOnUser)' an"
                                    }
                                }
                            }
                        } catch {
                            $out += "  Fehler bei der Benutzerkontext-Analyse: $_"
                            $out += "  Erweiterte Diagnose fehlgeschlagen"
                        }
                        #endregion
                    }
                }
            } catch {
                $out += Write-Status "LDAP-Verbindungsfehler: $_" 'CRIT'
            }
            #endregion
        } else {
            $out += Write-Status "Computer ist NICHT Teil einer Domäne. Arbeitsgruppe: $($computerSystem.Workgroup)" 'WARN'
        }
    } catch {
        $out += "Fehler beim Abrufen der Domäneninformationen: $_"
    }

    $out -join "`n"
}

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

# Sammeln der Ergebnisse aus parallelen Aufgaben
Write-Progress -Activity "Sammle Ergebnisse der parallelen Aufgaben" -Status "Bitte warten..."
$parallelResults = Get-ParallelResults -Jobs $parallelJobs
$SystemData["SystemEvents"] = $parallelResults["SystemEvents"]
$SystemData["InstalledSoftware"] = $parallelResults["InstalledSoftware"]
$SystemData["WindowsUpdates"] = $parallelResults["WindowsUpdates"]

# Aufräumen
$runspacePool.Close()
$runspacePool.Dispose()

#endregion
#region REPORT GENERATION
# Bericht zusammenstellen
$Report = @()
$Report += "===================================="
$Report += "📋 SYSTEMBERICHT $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
$Report += "===================================="
$Report += "🔑 Ausgeführt als: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
if ($elevatedContext -and $actualLoggedInUser -and $currentUser -ne $actualLoggedInUser) {
    $Report += "👤 Angemeldeter Benutzer: $actualLoggedInUser"
}
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
