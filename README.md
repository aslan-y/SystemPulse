# SystemPulse
Ein leistungsstarkes PowerShell-Diagnosetool für Windows-Systeme, das automatisch Hardware, Software, Netzwerk und Sicherheit analysiert. Mit visuellen Statusindikatoren, kritischer Problemerkennung und umfassender AD-Integration ideal für Administratoren. Erstellt übersichtliche Berichte für schnelle Systemanalyse und Fehlerdiagnose.

#📋 Funktionen
SystemPulse sammelt detaillierte Informationen zu:

🖥️ System: Betriebssystem, BIOS, Uptime
🔧 Hardware: CPU, RAM, Grafikkarten, Speichermedien
⚡ Performance: CPU/RAM-Auslastung, Top-Prozesse
💽 Speicher: Laufwerke, Gesundheitsstatus, BitLocker
🌐 Netzwerk: Adapter, Konnektivität, DNS-Einstellungen
⚙️ Dienste: Automatische Dienste und deren Status
🚀 Autostart: Startprogramme aus Registry und Startup-Ordner
🛡️ Sicherheit: Windows Defender, Firewall, Bedrohungen
🔒 Sicherheitslog: Fehlgeschlagene Anmeldeversuche
🌐 Active Directory: Domäneninformationen, GPO-Status, Kerberos
⚠️ Ereignisse: Kritische Systemfehler und Warnungen
Alle Ergebnisse werden mit visuellen Indikatoren (🟢🟡🔴) für eine schnelle Problemidentifikation angezeigt.

#⚙️ Anforderungen
Windows 10/11 oder Windows Server 2016+
PowerShell 5.1 oder höher
Administratorrechte

🚀 Installation
Lade das Skript herunter
Optional: Überprüfe die Signatur oder entferne die Ausführungsbeschränkung:
````
Unblock-File -Path .\SystemPulse.ps1
````

Das Skript zeigt einen Datei-Dialog zur Auswahl des Speicherorts für den Bericht und erzeugt:

Echtzeitfeedback in der Konsole
Eine detaillierte Textdatei mit dem Systemdiagnosebericht
````
====================================
📋 SYSTEMBERICHT 2025-08-14 10:15
====================================
🔑 Aktueller Benutzer: Administrator
🖥 Computername: LAPTOP
👤 Mit Admin-Rechten: True
====================================
📊 ZUSAMMENFASSUNG:

⚠️ ZUSAMMENFASSUNG KRITISCHER PUNKTE

Services: 🟡 Automatische Dienste nicht gestartet:
DefenderStatus: 🟡 Letzter Komplett-Scan: Nie durchgeführt
SecurityLog: 🟡 Letzte fehlgeschlagene Logons:
````
🔍 Active Directory Integration
In Domänenumgebungen bietet SystemPulse erweiterte Funktionen:
Domänenmitgliedschaftsstatus und -konfiguration
Gruppenrichtlinien-Analyse und Fehlersuche
Kerberos-Ticket-Status und LDAP-Konnektivität
Detaillierte Computerkonteninformationen

#📜 Lizenz
MIT-Lizenz - siehe LICENSE

#Autor
Yasin Aslan


