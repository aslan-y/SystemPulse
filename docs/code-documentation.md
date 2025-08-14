## SystemPulse - Code-Dokumentation

# Skriptstruktur
Das SystemPulse-Skript ist in mehrere logische Regionen unterteilt, die verschiedene Aspekte der Funktionalität kapseln:
````
#region SETUP & PREREQUISITES
#region HELPER FUNCTIONS
#region DATA COLLECTION
#region CRITICAL POINTS SUMMARY
#region REPORT GENERATION
````

# Hauptfunktionen und ihre Aufgaben
1. Setup & Vorbedingungen
````
# Admin-Check
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Dateiauswahl-Dialog
$saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
````
Diese Sektion prüft Vorbedingungen wie Administratorrechte und initialisiert grundlegende Variablen. Der Dateiauswahl-Dialog ermöglicht dem Benutzer, den Speicherort für den Bericht zu bestimmen.

2. Hilfsfunktionen
````
function Get-SystemData {
    param (
        [string]$Command,
        [scriptblock]$ScriptBlock
    )
    # ...
}

function Write-Status {
    param(
        [string]$Text,
        [string]$Level
    )
    # ...
}

function Get-CounterSafe {
    param(
        [string[]]$PossibleNames,
        [string]$Label,
        [string]$Unit = ''
    )
    # ...
}
````
Get-SystemData: Zentrale Funktion, die Systeminformationen sammelt und Fehlerbehandlung implementiert.

Parameter:
$Command - Beschreibung der auszuführenden Aktion
$ScriptBlock - Der auszuführende Code
Write-Status: Formatiert Statusmeldungen mit visuellen Indikatoren.

Parameter:
$Text - Der anzuzeigende Text
$Level - Statuslevel (OK, WARN, CRIT)
Rückgabe: Formatierte Statuszeile mit Emoji-Indikator
Get-CounterSafe: Robuste Abfrage von Performance-Countern mit Mehrsprachunterstützung.

Parameter:
$PossibleNames - Array möglicher Counter-Namen
$Label - Beschriftung für die Ausgabe
$Unit - Einheit des Messwerts (optional)

3. Datensammlung
````
$SystemData = @{}

# Systeminformationen
$SystemData.SystemInfo = Get-SystemData "Systeminformationen" {
    # ...
}

# Active Directory & GPO
$SystemData.ActiveDirectoryInfo = Get-SystemData "Active Directory & GPO" {
    # ...
}
````
In dieser Region werden verschiedene Datensammler definiert, die jeweils einen Aspekt des Systems analysieren. Jeder Sammler:

Verwendet Get-SystemData für konsistente Fehlerbehandlung
Führt spezifische Abfragen durch
Formatiert die Ergebnisse mit Write-Status für visuelle Indikation
Speichert die Ergebnisse im $SystemData-Hashtabl

4. Zusammenfassung kritischer Punkte
````
# Sammeln der kritischen Punkte
$CriticalPoints = @()

foreach ($key in $SystemData.Keys) {
    # Suche nach Warnungen und kritischen Zuständen
    if ($content -match "🔴|🟡") {
        # ...
    }
}
````
Diese Sektion analysiert alle gesammelten Daten, extrahiert Warnungen und kritische Punkte und erstellt eine Zusammenfassung für den Bericht.

5. Berichtsgenerierung
````
# Bericht zusammenstellen
$Report = @()
# ...

# Definierte Reihenfolge der Abschnitte
$orderedSections = @(
    # Zusammenfassung immer zuerst
    # 1. System-Basisinformationen
    'SystemInfo',
    'ActiveDirectoryInfo',
    # ...
)

# Abschnitte in definierter Reihenfolge hinzufügen
foreach ($section in $orderedSections) {
    # ...
}
````
Diese Sektion:
Erstellt die Berichtsstruktur
Ordnet die Abschnitte in einer definierten Reihenfolge an
Fügt Kategorie-Icons und Formatierung hinzu
Speichert den Bericht in der ausgewählten Datei

# Datenfluss
Initialisierung: Überprüfung der Vorbedingungen, Anzeige des Dateiauswahldialogs
Datensammlung: Jede Systemkomponente wird analysiert und die Ergebnisse im $SystemData-Hashtable gespeichert
Analyse: Kritische Punkte werden identifiziert und in eine Zusammenfassung extrahiert
Berichtsgenerierung: Die Daten werden strukturiert und formatiert
Ausgabe: Der Bericht wird in eine Datei geschrieben und wichtige Informationen in der Konsole angezeigt

# Erweiterungspunkte
Neue Datensammler hinzufügen
````
# Neuer Datensammler
$SystemData.NeuerBereich = Get-SystemData "Beschreibung" {
    $out = @()
    # Daten sammeln und formatieren
    $out -join "`n"
}
````
Neue Kategorie in den Bericht einfügen
````
# Zur Reihenfolge hinzufügen
$orderedSections = @(
    # ...
    'NeuerBereich',
    # ...
)

# Icon hinzufügen
$categoryIcon = switch ($section) {
    # ...
    'NeuerBereich' { "🆕 NEUE KATEGORIE" }
    # ...
}
````

# Hinweise zur Fehlerbehandlung
Das Skript verwendet durchgängig Try-Catch-Blöcke und -ErrorAction SilentlyContinue, um robustes Verhalten bei Fehlern zu gewährleisten. Jede Komponente ist isoliert, sodass ein Fehler in einem Bereich nicht das gesamte Skript beeinträchtigt.

Diese Dokumentation bietet einen Überblick über die Struktur und Funktionsweise des SystemPulse-Skripts und dient als Referenz für zukünftige Erweiterungen und Anpassungen.
