## Contributing to SystemPulse
Vielen Dank für dein Interesse, zu SystemPulse beizutragen! Dieses Dokument bietet Richtlinien und Informationen, wie du zum Projekt beitragen kannst.

# Inhaltsverzeichnis
Verhaltenskodex
Wie kann ich beitragen?
Entwicklungsumgebung einrichten
Coding Standards
Pull Request Prozess
Testen
Dokumentation
Kommunikation
Verhaltenskodex
Wir erwarten von allen Mitwirkenden, dass sie respektvoll und konstruktiv miteinander umgehen. Bitte halte dich an folgende Grundsätze:
Sei respektvoll und inklusiv gegenüber anderen
Akzeptiere konstruktive Kritik
Fokussiere dich auf das, was für die Community am besten ist
Zeige Empathie gegenüber anderen Community-Mitgliedern

## Wie kann ich beitragen?
Es gibt viele Möglichkeiten, zum Projekt beizutragen:
1. Fehler melden
Prüfe zuerst, ob der Fehler bereits gemeldet wurde
Nutze die Issue-Vorlage und fülle alle erforderlichen Informationen aus
Füge klare Schritte zur Reproduktion hinzu
Füge Screenshots oder Logs bei, wenn möglich
2. Feature-Vorschläge
Beschreibe das gewünschte Feature und warum es nützlich wäre
Erkläre, wie es umgesetzt werden könnte
Diskutiere Alternativen, die du in Betracht gezogen hast
3. Code-Beiträge
Suche nach Issues mit dem Label "good first issue" für Einsteiger
Kommentiere das Issue, an dem du arbeiten möchtest
4. Dokumentation verbessern
Verbessere oder erweitere die README
Füge Beispiele oder Tutorials hinzu
Korrigiere Tippfehler oder unklare Formulierungen
Entwicklungsumgebung einrichten

# Voraussetzungen:

Windows 10/11 oder Windows Server 2016+
PowerShell 5.1 oder höher
Visual Studio Code mit PowerShell-Erweiterung
Git
````
git clone https://github.com/aslan-y/SystemPulse.git
cd SystemPulse
````
PowerShell-Module: Stelle sicher, dass alle notwendigen Module installiert sind:
````
# Beispiel für optionale Module für Entwicklung
Install-Module -Name Pester -Scope CurrentUser -Force
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force
````

# Coding Standards
Bitte befolge diese Standards bei der Entwicklung für SystemPulse:
Namenskonventionen:
Verwende PascalCase für Funktionen und CmdLets: Get-SystemData
Verwende camelCase für Variablen: $errorCount
Verwende aussagekräftige Namen
Stil:
Einrückung: 4 Leerzeichen (keine Tabs)
Maximale Zeilenlänge: 120 Zeichen
Verwende Leerzeilen, um den Code logisch zu gliedern
Kommentare und Dokumentation:
Jede Funktion sollte einen Kommentarblock mit Synopsis und Parameterbeschreibungen haben
Nutze inline-Kommentare für komplexe Logik
Halte Kommentare aktuell, wenn du Code änderst
Best Practices:
Folge dem Prinzip "Eine Funktion, eine Aufgabe"
Schreibe fehlertoleranten Code mit try/catch-Blöcken
Nutze die PowerShell-Pipe wo sinnvoll
Vermeide hartcodierte Pfade oder Zeichenketten
Pull Request Prozess
Branch erstellen:
````
git checkout -b feature/deine-feature-beschreibung
````
Regelmäßig committen:
````
git add .
git commit -m "Beschreibender Commit-Text"
````
Vor dem PR:
Führe Invoke-ScriptAnalyzer auf deinen Code aus
Führe Tests durch, falls vorhanden
Stelle sicher, dass dein Code gut dokumentiert ist
PR erstellen:
Beschreibe klar, was dein PR tut
Verweise auf zugehörige Issues
Beantworte Review-Kommentare und nehme Änderungen vor
Merge: Nach erfolgreicher Review wird dein PR vom Projektbetreuer gemergt.


# Testen
Wir empfehlen, für neue Funktionen Tests zu schreiben:
Manuelle Tests:
Teste deine Änderungen in verschiedenen Umgebungen
Teste sowohl positive als auch negative Szenarien
Automatisierte Tests (optional):
Nutze Pester für Unit-Tests
Platziere Tests im Tests-Verzeichnis
Benenne Testdateien nach dem Schema FunktionsName.Tests.ps1

# Dokumentation
Gute Dokumentation ist entscheidend:
Aktualisiere die README.md, wenn sich Funktionalitäten ändern
Dokumentiere neue Parameter oder Funktionen
Füge Beispiele hinzu, wie neue Features genutzt werden können
Wenn du ein neues Modul hinzufügst, dokumentiere seine Funktion und Abhängigkeiten

# Kommunikation
Nutze GitHub Issues für Fehlerberichte und Feature-Anfragen
Stellen Fragen in Diskussionen oder direkt in Issues
Sei geduldig und respektvoll in der Kommunikation
Halte Issues und PRs aktuell, wenn sich etwas ändert

Nochmals vielen Dank für dein Interesse an SystemPulse! Deine Beiträge helfen dabei, dieses Tool besser und nützlicher für alle zu machen.
