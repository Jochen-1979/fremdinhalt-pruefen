# fremdinhalt-pruefen

Ein Skill für [Claude Code](https://code.claude.com/docs), der fremde Prompts, Skills und Agenten-Anweisungen auf Prompt-Injektion prüft, bevor man sie ausführt oder übernimmt. Gedacht für alles, was man aus Video-Communitys, Foren oder GitHub-Repos holt.

> **Wichtiger Hinweis:** Dieser Skill ist ein Hilfsmittel zur Vorprüfung. Er erkennt nicht jede Prompt-Injektion und ersetzt keine eigene Prüfung. Ein unauffälliges Ergebnis ist kein Freibrief. Die Nutzung erfolgt auf eigene Verantwortung, siehe auch die [Lizenz](LICENSE).

## Wie er arbeitet

Keine Stufe reicht allein, deshalb sind es vier:

1. **Statischer Scan** (`scan.py`, nur Python-Standardbibliothek): versteckte und unsichtbare Zeichen, HTML-Tricks, Übernahme-Formulierungen, Netz-, Installations- und Schreibbefehle, getarnte Programmdateien, ZIP-Inhaltsverzeichnisse, Verweise nach außen, verdächtige Dateinamen. Mit einem Selbsttest aus weit über hundert Fällen.
2. **Lesende Prüfung** durch einen eigenen Prüfagenten, der nur Lesewerkzeuge hat. Er hält jede Anweisung gegen ein Erwartungsprofil, das du vorher selbst festlegst, und meldet GRÜN, GELB, ROT oder UNVOLLSTÄNDIG.
3. **Freigabe durch dich.** Der Skill empfiehlt nur.
4. **Eingeschränkter Ausführungsrahmen:** Freigegebene Prompts laufen in einer eigenen Sitzung mit Sperr-Vorlage, jeder Befehl wird einzeln bestätigt.

Geprüfte Stände landen mit SHA-256 in einem Prüfregister. Dieselbe Datei wird so nicht doppelt geprüft, und eine geänderte Fassung fällt auf.

## Voraussetzungen

- Claude Code als CLI oder Desktop-App, für die Lesesperre der Ausführungsvorlage ab Version 2.1.257
- Python 3.12 oder neuer, nur Standardbibliothek
- Getestet unter Windows 11. Unter macOS und Linux ist der Skill nicht getestet, sollte aber laufen.
- Dein Benutzerordner hat eine der üblichen Formen `C:\Users\<Name>`, `/Users/<Name>` oder `/home/<Name>`. Nur dort erkennt der Prüfagent den Sichtungsordner. Bei anderen Formen (etwa `/root` oder ein umgeleitetes Windows-Profil) lehnt er jede Prüfung als UNVOLLSTÄNDIG ab.

## Installation

Das Repo spiegelt die Zielstruktur. Beide `.claude`-Teile entweder nach `~/.claude/` kopieren (dann gilt der Skill in jedem Projekt) oder in den `.claude`-Ordner eines einzelnen Projekts.

**Windows (PowerShell, aus dem entpackten Repo-Ordner):**

```powershell
New-Item -ItemType Directory -Force "$HOME\.claude\skills", "$HOME\.claude\agents" | Out-Null
Copy-Item -Recurse .\.claude\skills\fremdinhalt-pruefen "$HOME\.claude\skills\"
Copy-Item .\.claude\agents\fremdinhalt-leser.md "$HOME\.claude\agents\"
```

**macOS und Linux:**

```bash
mkdir -p ~/.claude/skills ~/.claude/agents
cp -R ./.claude/skills/fremdinhalt-pruefen ~/.claude/skills/
cp ./.claude/agents/fremdinhalt-leser.md ~/.claude/agents/
```

**Nur für ein Projekt** statt global: dieselben Befehle, aber mit dem `.claude`-Ordner des Projekts als Ziel, zum Beispiel `<Projekt>\.claude\skills\` und `<Projekt>\.claude\agents\` (Windows) oder `<Projekt>/.claude/skills/` und `<Projekt>/.claude/agents/` (macOS, Linux).

Danach Claude Code neu starten. Neue Skills und Agenten lädt Claude Code erst beim Sitzungsstart.

**Aktualisieren.** Vor dem Kopieren einer neuen Fassung `pruefregister.json` aus dem installierten Skill-Ordner sichern, dann den alten Ordner `fremdinhalt-pruefen` entfernen (sonst entsteht beim Kopieren ein verschachtelter Ordner), neu kopieren und das gesicherte Register zurücklegen.

**Arbeitsordner anlegen.** Der Prüfagent liest nur im Sichtungsordner, der Pfad ist fest:

```powershell
New-Item -ItemType Directory -Force "$HOME\fremdinhalt\sichtung", "$HOME\fremdinhalt\ausfuehrung" | Out-Null
```

```bash
mkdir -p ~/fremdinhalt/sichtung ~/fremdinhalt/ausfuehrung
```

Im Benutzerordner und in `~/fremdinhalt/` darf keine Datei `CLAUDE.md` liegen. Claude Code lädt sie sonst auch in der Ausführungssitzung. Deine eigenen Anweisungen in `~/.claude/CLAUDE.md` und `~/.claude/rules/` sowie Hooks und MCP-Server aus deinen Benutzer-Einstellungen gelten dort ebenfalls. Prüfe einmal, ob davon etwas Netz- oder Schreibzugriffe auslöst.

**Funktionsprobe:**

```powershell
python -B -X utf8 -I "$HOME\.claude\skills\fremdinhalt-pruefen\scripts\testsatz.py"
```

```bash
python3 -B -X utf8 -I ~/.claude/skills/fremdinhalt-pruefen/scripts/testsatz.py
```

Erwartung: Schlusszeile `n von n Faellen bestanden` (beide Zahlen gleich), Exit-Code 0. Wird `python` unter Windows nicht gefunden, `py -3` versuchen. Meldet der Test eine zu alte Python-Version, Python 3.12 oder neuer installieren. Steht in der Schlusszeile „uebersprungen“, konnte der Test keine Verknüpfung (Junction oder Symlink) anlegen. Er endet dann mit Exit-Code 1, und die Prüfung von Verweisen ist auf deinem System nicht bestätigt.

## Anpassen

Die Sperr-Vorlage `vorlagen/ausfuehrung-settings.json` verbietet der Ausführungssitzung bereits das Lesen von Dokumenten-, Desktop- und Download-Ordnern, OneDrive, SSH-Schlüsseln, Claude-Code-Einstellungen, Cloud-Zugängen und `.env`-Dateien. Liegen deine Notizen oder Projekte woanders, ergänze unter `deny` eine Zeile:

- Windows: `"Read(//d/Projekte/**)"` für `D:\Projekte` (Laufwerksbuchstabe klein, Schrägstriche statt Backslashes)
- macOS und Linux: `"Read(~/Projekte/**)"`

Die Schreibweise mit Laufwerksbuchstaben und die Sperre `//**/.env` folgen der Claude-Code-Doku, sind aber nicht selbst getestet. Nimm deshalb einen eigenen Pfad und eine `.env`-Datei in den Kanarien-Test unten auf.

## Benutzung

In Claude Code, im Berechtigungsmodus **mit Rückfrage** (nicht im Auto-Modus):

```
/fremdinhalt-pruefen "~/Downloads/Fremder-Prompt.md"
```

Für fremde Skills oder Repos den Ordner angeben. Claude führt dich durch den Ablauf: Register-Abgleich, Kopie in den Sichtungsordner, Erwartungsprofil per Klickfrage, Scan, lesende Prüfung, Bericht mit Empfehlung, Freigabe, Ausführungsrahmen und Aufräumen. Die Einzelheiten stehen in `SKILL.md`.

## Kanarien-Test der Sperr-Vorlage

Einmal nach der Einrichtung und nach jeder Änderung an der Vorlage prüfen, ob die Sperren bei deiner Claude-Code-Fassung wirken:

1. Ordner `~/fremdinhalt/ausfuehrung/test/.claude/` anlegen und die Vorlage dorthin als `settings.json` kopieren.
2. In `~/fremdinhalt/ausfuehrung/test/` eine Claude-Code-Sitzung öffnen.
3. Claude nacheinander bitten: eine Datei aus deinem Dokumente-Ordner zu lesen · `~/.gitconfig` zu lesen · eine `.env`-Datei zu lesen, die du vorher zum Testen in `~/fremdinhalt/ausfuehrung/test/` angelegt hast · mit seinem Dateiwerkzeug eine neue Datei anzulegen · eine Websuche zu machen · unter Windows `Invoke-WebRequest https://example.com` auszuführen, unter macOS/Linux `curl https://example.com`.
4. Erwartung: Alle sechs werden ohne Rückfrage abgelehnt. Fragt Claude bei einem davon um Erlaubnis, statt abzulehnen, greift diese Sperre nicht. Dann die Anfrage ablehnen. Bei anderen Shell-Befehlen ist eine Rückfrage dagegen gewollt, denn Bash und PowerShell stehen auf „nachfragen“.
5. Lädt Claude Code die Einstellungsdatei mit einer Warnung zu unbekannten Schlüsseln oder Werkzeugnamen, die betroffenen Zeilen aus der Vorlage entfernen. Sie stammen aus einer neueren Claude-Code-Fassung.

## Grenzen

- Kein Verfahren schließt Prompt-Injektion sicher aus. Der Scan kennt nur bekannte Muster. Umgebrochene, umformulierte oder anderssprachige Anweisungen findet er oft nicht.
- Der Prüfagent ist selbst ein Sprachmodell und kann getäuscht werden. Seine Pfadgrenze ist eine Anweisung, keine technische Sperre.
- Befehlssperren lassen sich umgehen, etwa über Python mit eigenem Netzcode. Die eigentliche Sicherung ist, dass du jeden Befehl bewusst freigibst.
- Inhalte hinter Links und in Archiven prüft der Skill nicht.
- Die Ausführungsvorlage ist für lesende Prompts gedacht (beraten, auswerten, Bericht schreiben). Einrichtungs-Prompts, die installieren und schreiben, brauchen einen eigenen, bewusst erweiterten Rahmen.

## Entstehung

Der Skill ist für den eigenen Gebrauch entstanden und wurde vor der Veröffentlichung von zwei weiteren Sprachmodellen unabhängig begutachtet. Die dabei gefundenen Schwachstellen sind behoben und durch Testfälle belegt, die bekannten Lücken stehen oben unter „Grenzen“.

## Mitmachen

Neue Angriffsmuster bitte zuerst als Fall in `scripts/testsatz.py` aufnehmen (der Test schlägt fehl), dann `scan.py` erweitern (der Test besteht). Beide Skripte bleiben reines ASCII. Nach jeder Änderung den Selbsttest laufen lassen.

## Lizenz

[MIT](LICENSE)
