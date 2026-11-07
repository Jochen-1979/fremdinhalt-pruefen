#!/usr/bin/env python3
# Statischer Scan fremder Prompt-, Skill- und Anweisungsdateien auf Prompt-Injektion.
# Teil des Skills fremdinhalt-pruefen. Nur Standardbibliothek, Datei strikt ASCII.
# Aufruf:  python -B -X utf8 -I scan.py [--register <datei>] [--nur-register] [--erwartet <sha256>]
#                                     [--bericht <datei>] <datei-oder-ordner> [...]
#          python -B -X utf8 -I scan.py [--register <datei>] --register-liste
# Exit:    0 = kein ROT, kein GELB und jede Datei als Text gescannt (INFO moeglich, etwa URLs)
#          1 = nur GELB, oder mindestens eine Datei nicht als Text gescannt (Bild, Schrift, Archiv, Binaerdaten,
#              Datei ueber 20 MiB: nur der Dateikopf wird geprueft, ein Programmkopf bleibt ROT)
#          2 = mindestens ein ROT
#          mit --nur-register: 0 = jedes Ziel mit gleicher Pruefsumme im Register, 3 = mindestens eins neu oder geaendert
#          4 = unvollstaendig, wiegt schwerer als ROT: Pfad fehlt oder nicht lesbar, keine Datei gefunden, Register
#              fehlt oder ungueltig, Ziel ist ein Verweis, Verweis im Ordner beim Register-Abgleich, Pruefsumme
#              weicht von --erwartet ab, Bericht nicht schreibbar, Python aelter als 3.12, Abbruch
#          64 = Aufruf falsch
# Ausgabe: kurz fuer den Agenten. Ergebnis zuerst, ROT einzeln ohne Zeilenauszug, GELB je Datei und Kategorie
#          gebuendelt, INFO nur gezaehlt. Die Vollausgabe mit Zeilenauszuegen und allen URLs schreibt --bericht in
#          eine Datei. Pfade, Namen und Treffer werden maskiert: druckbares ASCII bleibt, alles andere und der
#          Backtick erscheinen als Hex-Maskierung.
# Register: pruefregister.json neben dem Ordner scripts (feste Felder, volle SHA-256). Ausgegeben werden daraus nur
#          Datum, Name (maskiert), Ampel und Entscheidung, nie Quelle oder Befundtext.
# Der Scan meldet Muster, er bewertet sie nicht. Ein sauberer Scan ist kein Freibrief.

import datetime
import hashlib
import io
import json
import os
import re
import sys
import unicodedata
import zipfile

ROT, GELB, INFO = 'ROT', 'GELB', 'INFO'

TEXT_ENDUNGEN = {'.md', '.txt', '.json', '.yaml', '.yml', '.toml', '.xml', '.html', '.htm', '.csv', ''}
HTML_ENDUNGEN = {'.html', '.htm', '.xhtml', '.svg'}
CODE_ENDUNGEN = {'.py', '.ps1', '.psm1', '.sh', '.bash', '.js', '.mjs', '.cjs', '.ts', '.bat', '.cmd', '.vbs', '.rb', '.pl', '.php', '.exe', '.dll', '.so'}
EXIT_UNVOLLSTAENDIG = 4
EXIT_AUFRUF = 64
MAX_ROT_ZEILEN = 100     # Kurzausgabe: danach Verweis auf --bericht; Werkzeuggrenze des Agenten 30.000 Zeichen
MAX_GELB_ZEILEN = 80
MAX_ZEILENNUMMERN = 12
MAX_BYTES = 20 * 1024 * 1024   # groessere Dateien: GELB Zu gross, nur Kopf geprueft, Pruefsumme trotzdem vollstaendig
KOPF_BYTES = 64 * 1024         # so viel liest die Kopf-Erkennung bei zu grossen Dateien
BLOCK_BYTES = 1024 * 1024      # Blockgroesse fuer die Pruefsumme
MINDEST_PYTHON = (3, 12)       # os.path.isjunction

# Dateikopf-Erkennung; Bytes als Hex, damit die Datei ASCII bleibt
H = bytes.fromhex
KOPF_ROT = [
    (H('7f454c46'), 'ELF-Programm (Linux)'),
    (H('feedface'), 'Mach-O-Programm (macOS)'),
    (H('feedfacf'), 'Mach-O-Programm (macOS)'),
    (H('cefaedfe'), 'Mach-O-Programm (macOS)'),
    (H('cffaedfe'), 'Mach-O-Programm (macOS)'),
    (H('cafebabe'), 'Java-Klasse oder Mach-O-Universalprogramm'),
    (H('0061736d'), 'WebAssembly-Modul'),
    (H('4c0000000114020000000000c000000000000046'), 'Windows-Verknuepfung (LNK)'),
    (H('d0cf11e0a1b11ae1'), 'OLE-Container (MSI, altes Office mit Makros)'),
    (b'ITSF', 'Kompilierte Hilfe (CHM)'),
]
PYC_FLAGS = (H('00000000'), H('01000000'), H('03000000'))
ZIP_KOEPFE = (H('504b0304'), H('504b0506'), H('504b0708'))
# ZIP-Container, die Code installieren oder Makros tragen
PAKET_ENDUNGEN = {'.jar', '.war', '.ear', '.whl', '.egg', '.nupkg', '.vsix', '.xpi', '.crx', '.apk', '.appx', '.msix',
                  '.docm', '.dotm', '.xlsm', '.xltm', '.xlam', '.pptm', '.potm', '.ppam'}
KOPF_ARCHIV = [
    (H('1f8b'), 'gzip'),
    (H('377abcaf271c'), '7z'),
    (b'Rar!\x1a\x07', 'RAR'),
    (H('fd377a585a00'), 'xz'),
    (H('28b52ffd'), 'zstd'),
]
ARCHIV_HINWEIS = 'Dateien darin nicht gescannt, entpacken und einzeln scannen'
ZIP_LISTE_MAX = 30
KOPF_MEDIEN = [
    (H('89504e470d0a1a0a'), 'PNG'), (H('ffd8ff'), 'JPEG'), (b'GIF87a', 'GIF'), (b'GIF89a', 'GIF'),
    (H('00000100'), 'ICO'), (b'wOFF', 'WOFF'), (b'wOF2', 'WOFF2'), (H('00010000'), 'TrueType'), (b'OTTO', 'OpenType'),
]

# (Kategorie, Stufe, Regex). Punkte vor Dateinamen als \x2e, damit Sicherheits-Hooks
# den Quelltext nicht als Dateizugriff werten.
MUSTER = [
    ('HTML-Kommentar', ROT, r'<!--|-->'),
    ('Verstecktes HTML', ROT, r'(?i)<\s*(iframe|object|embed)\b|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|(?<![\w-])hidden\b\s*(=|>)'),
    # In HTML-Dateien erwartbar, dort GELB (scan_text)
    ('Skript-/Stilblock', ROT, r'(?i)<\s*(script|style)\b'),
    ('HTML-Tag', GELB, r'(?i)<\s*(img|details|summary|div|span|a)\b'),
    ('Markdown-Bild', ROT, r'(?i)!\[[^\]]*\]\(\s*https?://'),
    ('Leerer Link', GELB, r'\[\s*\]\('),
    # Ausrufezeichen + Befehl in Backticks fuehrt Claude Code beim Laden eines Skills aus
    ('Inline-Befehl beim Laden', ROT, r'!`[^`]+`'),
    # Kandidaten; scan_text trennt Hex-Werte (INFO) und verlangt fuer ROT Gross-, Kleinbuchstaben und Ziffern
    ('Base64-artig', ROT, r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])'),
    ('Netz/Download', GELB, r'(?i)\b(curl|wget|invoke-webrequest|invoke-restmethod|iwr|irm|start-bitstransfer|webclient|webfetch|websearch|socket|netcat|ncat|scp|rsync|ftp|ngrok|webhook)\b'),
    ('Ausfuehren/Installieren', GELB, r'(?i)\b(iex|invoke-expression|eval|exec|subprocess|os\x2esystem|pip|pipx|npm|npx|uvx|winget|choco|brew|apt|apt-get|msiexec|start-process|encodedcommand|frombase64string|base64|powershell\s+-e)\b|\|\s*(sh|bash|iex|python)\b'),
    ('Schreiben/Loeschen', GELB, r'(?i)\b(rm\s+-|del\s+/|remove-item|set-content|out-file|add-content|copy-item|move-item|git\s+push|git\s+commit|git\s+remote|reg\s+add|set-itemproperty|schtasks|crontab|chmod|icacls)\b'),
    ('Geheimnisse/Konfiguration', GELB, r'(?i)(\x2eenv\b|\x2essh\b|id_rsa|id_ed25519|\x2eclaude\b|settings(\x2elocal)?\x2ejson|claude\x2emd|agents\x2emd|\x2emcp\x2ejson|\bhooks?\b|api[_ -]?key|access[_ -]?token|auth[_ -]?token|bearer|passw|secret|credential|private[_ -]?key|cookie|keychain|vaultwarden|\x2eaws\b|git/config|zugangsdaten|kennwort)'),
    ('Uebernahme-Formulierung', ROT, r'(?i)(ignore\s+(all\s+)?(previous|prior|above|earlier)|disregard\s+(all|any|the|previous)|forget\s+(your|all|previous)|you\s+are\s+now|new\s+instructions|system\s+prompt|developer\s+mode|jailbreak|ignorier\w*\s+(alle|die|deine|vorherige)|vergiss\s+(alle|deine|die)|deine\s+(bisherigen|vorherigen)\s+anweisungen|du\s+bist\s+(jetzt|ab\s+sofort|nun)\b)'),
    ('Rueckfragen abschalten', ROT, r'(?i)(ohne\s+(r\xfcck|rueck)frage|ohne\s+nachzufragen|frag\s+nicht|nicht\s+(nach)?fragen|ohne\s+best\xe4tigung|ohne\s+bestaetigung|without\s+(asking|confirmation)|do\s+not\s+ask|don\'t\s+ask|dangerously|skip-permissions|bypasspermissions|bypass|yolo|auto[\s-]?mode)'),
    ('Verschweigen', GELB, r'(?i)(nicht\s+erw\xe4hnen|nicht\s+erwaehnen|verschweig|sag\s+(ihm|ihr|dem\s+nutzer)\s+nicht|don\'t\s+(tell|mention)|do\s+not\s+(tell|mention|reveal)|geheim\s+halten|heimlich|silently|unbemerkt)'),
    ('URL', INFO, r'(?i)https?://[^\s)\]>"\']+|www\x2e[^\s)\]>"\']+'),
]
MUSTER = [(k, s, re.compile(r)) for k, s, r in MUSTER]
NAME_MUSTER = [m for m in MUSTER if m[0] in ('Inline-Befehl beim Laden', 'Uebernahme-Formulierung')]
HEX_LAUF = re.compile(r'[0-9a-fA-F]+')

UNSICHTBAR_BEREICHE = [
    (0xE0000, 0xE007F, 'Unicode-Tag-Zeichen (versteckter Text)'),
    (0x200B, 0x200F, 'Nullbreite-/Richtungszeichen'),
    (0x202A, 0x202E, 'Richtungs-Steuerzeichen'),
    (0x2060, 0x2064, 'Unsichtbare Verbinder/Operatoren'),
    (0x2066, 0x2069, 'Richtungs-Isolatoren'),
    (0xFE00, 0xFE0F, 'Variantenselektoren'),
    (0xE0100, 0xE01EF, 'Variantenselektoren (Zusatz)'),
    (0xFEFF, 0xFEFF, 'BOM/Nullbreite mitten im Text'),
    (0x00AD, 0x00AD, 'Weiches Trennzeichen'),
    (0x180E, 0x180E, 'Mongolischer Vokaltrenner'),
]


def unsichtbar(ch):
    o = ord(ch)
    for a, b, name in UNSICHTBAR_BEREICHE:
        if a <= o <= b:
            return name
    kat = unicodedata.category(ch)
    if kat in ('Cf', 'Co', 'Cn'):
        return 'Format-/Privatzeichen (%s)' % kat
    if kat == 'Cc' and ch not in '\t\r\n':
        return 'Steuerzeichen'
    return None


def schrift(ch):
    name = unicodedata.name(ch, '')
    for s in ('CYRILLIC', 'GREEK', 'ARMENIAN', 'CHEROKEE', 'FULLWIDTH', 'MATHEMATICAL'):
        if name.startswith(s):
            return s
    return None


URL_ZUGANG = re.compile(r'(?i)(://)[^/@\s]+@')


def maskieren(s):
    """Zugangsdaten in URLs (etwa aus .git/config) nie in die Ausgabe."""
    return URL_ZUGANG.sub(r'\1***@', s)


def zeige(s):
    """Fremden Text fuer die Ausgabe entschaerfen: druckbares ASCII bleibt (auch der Backslash in Pfaden),
    alles andere als Hex-Maskierung. Der Backtick wird zu \\x60, damit weder Inline-Befehl noch Code-Block
    entsteht. Zugangsdaten in URLs werden maskiert."""
    aus = []
    for ch in str(s):
        o = ord(ch)
        if 32 <= o < 127 and ch != '`':
            aus.append(ch)
        elif o < 0x100:
            aus.append('\\x%02x' % o)
        else:
            aus.append('\\U%08x' % o)
    return maskieren(''.join(aus))


def base64_echt(t):
    """Kandidat zaehlt nur mit Gross-, Kleinbuchstaben und Ziffer; lange Woerter und Pfade ohne Ziffer nicht."""
    return bool(re.search(r'[A-Z]', t) and re.search(r'[a-z]', t) and re.search(r'[0-9]', t))


def scan_text(text, endung=''):
    """Liefert Liste von Befunden (stufe, kategorie, zeile, detail, auszug). endung steuert HTML-Ausnahmen."""
    html = endung in HTML_ENDUNGEN
    befunde = []
    for nr, zeile in enumerate(text.split('\n'), 1):
        auszug = zeige(zeile.strip())[:140]
        # Unsichtbare Zeichen: Tag-Zeichen zusaetzlich dekodieren
        versteckt = {}
        tagtext = ''
        for ch in zeile:
            u = unsichtbar(ch)
            if u:
                versteckt[u] = versteckt.get(u, 0) + 1
                if 0xE0020 <= ord(ch) <= 0xE007E:
                    tagtext += chr(ord(ch) - 0xE0000)
        for name, n in versteckt.items():
            detail = '%s x%d' % (name, n)
            if tagtext and name.startswith('Unicode-Tag'):
                detail += ' | dekodiert: ' + zeige(tagtext)[:120]
            befunde.append((ROT, 'Unsichtbare Zeichen', nr, detail, auszug))
        # Fremde Schriften in lateinischen Woertern (Homoglyphen)
        for wort in re.findall(r'\w+', zeile):
            schriften = {schrift(c) for c in wort} - {None}
            if schriften and re.search(r'[A-Za-z]', wort):
                befunde.append((GELB, 'Homoglyphe', nr, '%s in %s' % ('/'.join(sorted(schriften)), zeige(wort)), auszug))
        for kat, stufe, rx in MUSTER:
            treffer = sorted({m.group(0) for m in rx.finditer(zeile)})
            if not treffer:
                continue
            if kat == 'Base64-artig':
                hexe = [t for t in treffer if HEX_LAUF.fullmatch(t)]
                if hexe:
                    befunde.append((INFO, 'Hash/Hex-Wert', nr, ', '.join(t[:16] + '...' for t in hexe[:5]), auszug))
                treffer = [t[:24] + '...' for t in treffer if not HEX_LAUF.fullmatch(t) and base64_echt(t)]
                if not treffer:
                    continue
            if kat == 'Skript-/Stilblock' and html:
                stufe = GELB
            befunde.append((stufe, kat, nr, ', '.join(zeige(t)[:60] for t in treffer[:5]), auszug))
    return befunde


def name_befunde(rel):
    """Dateinamen sind fremder Text: unsichtbare Zeichen, Inline-Befehle und Uebernahme-Formulierungen sind ROT."""
    befunde = []
    versteckt = sorted({unsichtbar(ch) for ch in rel} - {None})
    if versteckt:
        befunde.append((ROT, 'Dateiname', 0, 'unsichtbare oder Steuerzeichen im Pfad (%s): %s' % (
            ', '.join(versteckt), zeige(rel)[:120]), ''))
    for kat, _, rx in NAME_MUSTER:
        if rx.search(rel):
            befunde.append((ROT, 'Dateiname', 0, '%s im Pfad: %s' % (kat, zeige(rel)[:120]), ''))
    return befunde


def kopf_art(roh, name):
    """Erkennt nicht pruefbare Programmteile, Archive und Medien am Dateikopf, unabhaengig von der Endung.
    Liefert (stufe, beschreibung) oder None, wenn die Datei als Text zu behandeln ist."""
    endung = os.path.splitext(name)[1].lower()
    for kopf, art in KOPF_ROT:
        if roh.startswith(kopf):
            return ROT, art
    # PE nur mit Kennung PE\0\0 am Versatz aus 0x3C, sonst schlaegt jeder Text mit "MZ" am Anfang an
    if roh[:2] == b'MZ' and len(roh) >= 0x40:
        pe = int.from_bytes(roh[0x3c:0x40], 'little')
        if roh[pe:pe + 4] == b'PE\x00\x00':
            return ROT, 'Windows-Programm (PE)'
    # Python-Bytecode nach PEP 552: Magic (zweites Byte 0C bis 0E), CR LF, Flags 0, 1 oder 3
    if len(roh) >= 8 and 0x0c <= roh[1] <= 0x0e and roh[2:4] == b'\r\n' and roh[4:8] in PYC_FLAGS:
        return ROT, 'Python-Bytecode'
    if endung in ('.pyc', '.pyo'):
        return ROT, 'Python-Bytecode (Endung)'
    if roh.startswith(ZIP_KOEPFE):
        if endung in PAKET_ENDUNGEN:
            return ROT, 'ZIP-Paket mit Code oder Makros (%s)' % endung
        return GELB, 'Archiv (ZIP): ' + ARCHIV_HINWEIS
    for kopf, art in KOPF_ARCHIV:
        if roh.startswith(kopf):
            return GELB, 'Archiv (%s): %s' % (art, ARCHIV_HINWEIS)
    if roh[:3] == b'BZh' and roh[4:10] == bytes.fromhex('314159265359'):
        return GELB, 'Archiv (bzip2): ' + ARCHIV_HINWEIS
    if roh[257:262] == b'ustar':
        return GELB, 'Archiv (tar): ' + ARCHIV_HINWEIS
    if roh.startswith(b'%PDF-'):
        return GELB, 'PDF: kann Skripte und eingebettete Dateien tragen, nicht gescannt'
    for kopf, art in KOPF_MEDIEN:
        if roh.startswith(kopf):
            return INFO, 'Medien-/Schriftdatei (%s), nicht gescannt' % art
    return None


def textartig(text):
    """Hoechstens 1 Prozent Steuerzeichen ausser Tab, Zeilenumbruch, Wagenruecklauf und Seitenvorschub."""
    if not text:
        return False
    steuer = sum(1 for c in text if ord(c) < 32 and c not in '\t\n\r\x0c')
    return steuer <= len(text) // 100


def utf16_ohne_bom(roh):
    """Text in UTF-16 ohne BOM: jedes zweite Byte (fast) immer NUL."""
    if len(roh) < 4 or len(roh) % 2:
        return None
    for kodierung, nullen in (('utf-16-le', roh[1::2]), ('utf-16-be', roh[0::2])):
        if nullen.count(0) >= 0.9 * len(nullen):
            try:
                text = roh.decode(kodierung)
            except UnicodeDecodeError:
                continue
            if textartig(text):
                return text
    return None


def text_dekodieren(roh):
    """(text, hinweis): UTF-8 mit oder ohne BOM, UTF-16 mit BOM, UTF-16 ohne BOM, Text mit eingestreuten
    NUL-Bytes (NUL entfernt, Rest gescannt). Echte Binaerdaten: (None, hinweis)."""
    if roh[:2] in (b'\xff\xfe', b'\xfe\xff'):
        try:
            return roh.decode('utf-16'), 'UTF-16-Text'
        except UnicodeDecodeError:
            return None, 'UTF-16-BOM, aber nicht dekodierbar'
    if b'\x00' in roh:
        text = utf16_ohne_bom(roh)
        if text is not None:
            return text, 'UTF-16 ohne BOM'
        try:
            text = roh.replace(b'\x00', b'').decode('utf-8-sig')
        except UnicodeDecodeError:
            return None, 'NUL-Bytes'
        if not textartig(text):
            return None, 'NUL-Bytes'
        return text, 'NUL-Bytes x%d im Text, entfernt und Rest gescannt' % roh.count(b'\x00')
    try:
        return roh.decode('utf-8-sig'), ''
    except UnicodeDecodeError as e:
        return roh.decode('utf-8', 'replace'), 'kein gueltiges UTF-8: %s' % e


def kodierung_befunde(hinweis):
    if not hinweis:
        return []
    if hinweis.startswith('kein') or hinweis.startswith('NUL'):
        return [(ROT, 'Kodierung', 0, hinweis, '')]
    if 'ohne BOM' in hinweis:
        return [(GELB, 'Kodierung', 0, hinweis + ' (ungewoehnlich, kann Muster verbergen)', '')]
    return [(INFO, 'Kodierung', 0, hinweis, '')]


def zip_unsicher(name):
    """Eintragsname, der beim Entpacken ausserhalb des Zielordners landet (Zip-Slip)."""
    n = name.replace('\\', '/')
    return n.startswith('/') or re.match(r'[A-Za-z]:', n) is not None or '..' in n.split('/')


def zip_befunde(roh):
    """Inhaltsverzeichnis eines ZIP-Archivs, ohne zu entpacken: Liste (INFO), Pfade nach aussen (ROT),
    verschluesselte Eintraege (GELB), unlesbares Verzeichnis (GELB)."""
    try:
        with zipfile.ZipFile(io.BytesIO(roh)) as z:
            eintraege = [e for e in z.infolist() if not e.is_dir()]
    except (zipfile.BadZipFile, ValueError, NotImplementedError, EOFError) as e:
        return [(GELB, 'Archiv-Inhalt', 0, 'Inhaltsverzeichnis nicht lesbar (%s)' % zeige(e), '')]
    namen = [zeige(e.filename) for e in eintraege]
    groesse = sum(e.file_size for e in eintraege)
    liste = ', '.join(namen[:ZIP_LISTE_MAX])
    if len(namen) > ZIP_LISTE_MAX:
        liste += ' (+%d weitere)' % (len(namen) - ZIP_LISTE_MAX)
    befunde = [(INFO, 'Archiv-Inhalt', 0, '%d Datei%s, entpackt %d Bytes: %s' % (
        len(namen), '' if len(namen) == 1 else 'en', groesse, liste or 'leer'), '')]
    nach_aussen = [n for e, n in zip(eintraege, namen) if zip_unsicher(e.filename)]
    if nach_aussen:
        befunde.append((ROT, 'Archiv-Inhalt', 0, 'Pfad nach aussen beim Entpacken (Zip-Slip): %s' % ', '.join(nach_aussen[:5]), ''))
    geheim = [n for e, n in zip(eintraege, namen) if e.flag_bits & 0x1]
    if geheim:
        befunde.append((GELB, 'Archiv-Inhalt', 0, '%d Eintraege verschluesselt, Inhalt nicht pruefbar: %s' % (
            len(geheim), ', '.join(geheim[:5])), ''))
    return befunde


def text_befunde(text, hinweis, endung, info):
    befunde = kodierung_befunde(hinweis)
    info['gescannt'] = True
    info['zeilen'] = text.count('\n') + 1
    if endung in CODE_ENDUNGEN or text.startswith('#!'):
        befunde.append((GELB, 'Ausfuehrbarer Code', 0, 'vollstaendig lesen, nicht nur scannen', ''))
    return befunde + scan_text(text, endung)


def befunde_fuer_bytes(roh, name):
    """({'gescannt', 'zeilen'}, befunde) fuer den Inhalt einer Datei; name liefert die Endung.
    Ein erkannter Dateikopf verhindert den Textscan nicht: Ist der ganze Inhalt lesbarer Text ohne NUL-Bytes,
    wird er trotzdem gescannt (sonst schaltet ein Praefix wie GIF89a oder OTTO den Scan ab)."""
    endung = os.path.splitext(name)[1].lower()
    info = {'gescannt': False, 'zeilen': 0}
    art = kopf_art(roh, name)
    if art:
        stufe, text = art
        if endung and endung in TEXT_ENDUNGEN:
            text += ', getarnt als ' + endung
        kat = {ROT: 'Nicht pruefbarer Programmteil', GELB: 'Archiv/Dokument', INFO: 'Medien'}[stufe]
        befunde = [(stufe, kat, 0, text, '')]
        if roh.startswith(ZIP_KOEPFE):
            befunde += zip_befunde(roh)
        if b'\x00' in roh:
            return info, befunde
        try:
            klartext = roh.decode('utf-8-sig')
        except UnicodeDecodeError:
            return info, befunde
        befunde.append((GELB, 'Kopf passt nicht zum Inhalt', 0, 'Dateikopf wie oben erkannt, der Inhalt ist aber '
                        'lesbarer Text: trotzdem als Text gescannt', ''))
        return info, befunde + text_befunde(klartext, '', endung, info)
    text, hinweis = text_dekodieren(roh)
    if text is None:
        return info, [(GELB, 'Binaerdaten', 0, 'unbekannte Art (%s), nicht gescannt' % hinweis, '')]
    return info, text_befunde(text, hinweis, endung, info)


def datei_sha(pfad):
    """(SHA-256, Bytes) blockweise, ohne die Datei ganz in den Speicher zu laden."""
    h = hashlib.sha256()
    n = 0
    with open(pfad, 'rb') as f:
        while True:
            block = f.read(BLOCK_BYTES)
            if not block:
                break
            h.update(block)
            n += len(block)
    return h.hexdigest(), n


def zu_gross_befunde(anfang, name, groesse):
    """Befunde fuer eine Datei ueber MAX_BYTES: GELB Zu gross, dazu die Kopf-Erkennung auf den ersten
    KOPF_BYTES (ein Programm bleibt ROT). Der Inhalt wird nicht als Text gescannt."""
    befunde = [(GELB, 'Zu gross', 0, '%d Bytes, Grenze %d Bytes: nicht als Text gescannt' % (groesse, MAX_BYTES), '')]
    art = kopf_art(anfang[:KOPF_BYTES], name)
    if art:
        stufe, text = art
        kat = {ROT: 'Nicht pruefbarer Programmteil', GELB: 'Archiv/Dokument', INFO: 'Medien'}[stufe]
        befunde.insert(0, (stufe, kat, 0, text, ''))
    return befunde


def scan_datei(pfad, name=None):
    """Kopf, Befunde. Pruefsumme und Befunde stammen aus denselben gelesenen Bytes.
    Ueber MAX_BYTES wird nur der Kopf geprueft, die Pruefsumme laeuft blockweise ueber den Rest weiter.
    Lesefehler (OSError) gehen an den Aufrufer."""
    name = name or os.path.basename(pfad)
    with open(pfad, 'rb') as f:
        roh = f.read(MAX_BYTES + 1)
        if len(roh) > MAX_BYTES:
            h = hashlib.sha256(roh)
            groesse = len(roh)
            while True:
                block = f.read(BLOCK_BYTES)
                if not block:
                    break
                h.update(block)
                groesse += len(block)
            kopf = {'sha256': h.hexdigest(), 'bytes': groesse, 'bom': roh[:3] == b'\xef\xbb\xbf',
                    'gescannt': False, 'zeilen': 0}
            return kopf, zu_gross_befunde(roh, name, groesse)
    info, befunde = befunde_fuer_bytes(roh, name)
    kopf = {
        'sha256': hashlib.sha256(roh).hexdigest(),
        'bytes': len(roh),
        'bom': roh[:3] == b'\xef\xbb\xbf',
    }
    kopf.update(info)
    return kopf, befunde


def teile(rel):
    return rel.replace('\\', '/').split('/')


def git_pruefbar(rel):
    """Dateien in .git an der Wurzel, die Befehle ausloesen koennen: config, hooks (ohne .sample), info."""
    t = [x.lower() for x in teile(rel)]
    if len(t) < 2 or t[0] != '.git':
        return False
    if t[1:] == ['config']:
        return True
    if t[1] == 'hooks' and len(t) > 2:
        return not t[-1].endswith('.sample')
    return t[1] == 'info' and len(t) > 2


def git_datenbestand(rel):
    """Uebriger Inhalt eines .git-Ordners an der Wurzel (Objekte, Refs, Logs): wird gezaehlt, nicht gescannt.
    Eine Datei namens .git ist kein Datenbestand, sondern ein Verweis (gitdir) und wird gescannt."""
    t = teile(rel)
    return len(t) > 1 and t[0].lower() == '.git' and not git_pruefbar(rel)


def node_modules_pfad(rel):
    t = teile(rel)
    for i, teil in enumerate(t[:-1]):
        if teil.lower() == 'node_modules':
            return '/'.join(t[:i + 1])
    return None


def ordner_befunde(liste):
    """Befunde zu mitgelieferten Ordnern und .git-Dateien aus (relpfad, bytes); Namen ohne Ruecksicht auf
    Gross-/Kleinschreibung. Je Pfad zaehlt nur der oberste Ordner dieser Art."""
    gruppen = {}
    git_dateien = []
    for rel, groesse in liste:
        t = teile(rel)
        if t[-1].lower() == '.git':
            git_dateien.append(('/'.join(t), len(t)))
        for i, teil in enumerate(t[:-1]):
            n = teil.lower()
            if n in ('node_modules', '__pycache__', '.git'):
                g = gruppen.setdefault('/'.join(t[:i + 1]), [n, i, 0, 0])
                g[2] += 1
                g[3] += groesse
                break
    befunde = []
    for pfad in sorted(gruppen):
        n, tiefe, anzahl, groesse = gruppen[pfad]
        menge = '%d Datei%s, %d Bytes' % (anzahl, '' if anzahl == 1 else 'en', groesse)
        if n == '__pycache__':
            befunde.append((ROT, 'Mitgelieferter Ordner', 0, '%s (%s): Python-Bytecode, nicht pruefbar, '
                            'laeuft beim Import statt der Quelle. Abhilfe: Ordner in den Papierkorb, Python erzeugt ihn '
                            'bei Bedarf neu' % (zeige(pfad), menge), ''))
        elif n == 'node_modules':
            befunde.append((GELB, 'Mitgelieferter Ordner', 0, '%s (%s): Fremdpakete, gescannt, '
                            'Befunde ausser ROT gebuendelt' % (zeige(pfad), menge), ''))
        elif tiefe == 0:
            befunde.append((GELB, 'Mitgelieferter Ordner', 0, '.git an der Wurzel (%s): kein Voll-Klon erwartet; '
                            'config, hooks und info gescannt, Datenbestand nicht' % menge, ''))
        else:
            befunde.append((ROT, 'Mitgelieferter Ordner', 0, '.git unterhalb der Wurzel %s (%s): untergeschobenes '
                            'Repo, kann Befehle ausloesen' % (zeige(pfad), menge), ''))
    for pfad, tiefe in git_dateien:
        if tiefe == 1:
            befunde.append((GELB, 'Mitgelieferter Ordner', 0, '.git als Datei an der Wurzel: lenkt Git auf Metadaten '
                            'an anderer Stelle (gitdir), als Text gescannt; kein Voll-Klon erwartet', ''))
        else:
            befunde.append((ROT, 'Mitgelieferter Ordner', 0, '.git als Datei unterhalb der Wurzel %s: untergeschobener '
                            'Verweis auf Git-Metadaten, kann Befehle ausloesen' % zeige(pfad), ''))
    return befunde


def ist_verweis(pfad):
    """'Junction', 'Symlink' oder None. os.walk folgt Junctions trotz followlinks=False (Python 3.13)."""
    if os.path.isjunction(pfad):
        return 'Junction'
    if os.path.islink(pfad):
        return 'Symlink'
    return None


def verweis_ziel(pfad):
    """(Ziel als Text, Ziel vorhanden)."""
    try:
        z = os.readlink(pfad)
    except OSError:
        return '?', False
    if z.startswith('\\\\?\\'):
        z = z[4:]
    voll = z if os.path.isabs(z) else os.path.join(os.path.dirname(pfad), z)
    return z, os.path.exists(voll)


def verweis_befunde(liste):
    """ROT je Junction oder Symlink aus (relpfad, art, ziel, ziel vorhanden)."""
    befunde = []
    for rel, art, ziel, vorhanden in liste:
        befunde.append((ROT, 'Verweis nach aussen', 0, '%s %s -> %s%s: nicht verfolgt; beim Kopieren oder Ausfuehren '
                        'kann er Dateien ausserhalb des Ziels einbeziehen' % (
                            art, zeige(rel), zeige(ziel), '' if vorhanden else ' (Ziel fehlt)'), ''))
    return befunde


def alle_dateien(ziel, fehler, verweise=None):
    """(pfad, relpfad) aller Dateien. Kein Ordner wird uebersprungen. Junctions und Symlinks werden nicht verfolgt,
    sondern als (relpfad, art, ziel, vorhanden) in verweise gesammelt; Lesefehler landen in fehler."""
    if verweise is None:
        verweise = []
    if os.path.isfile(ziel) and not ist_verweis(ziel):
        yield ziel, os.path.basename(ziel)
        return
    stapel = ['']
    while stapel:
        rel_ordner = stapel.pop()
        ordner = os.path.join(ziel, rel_ordner) if rel_ordner else ziel
        try:
            with os.scandir(ordner) as it:
                eintraege = sorted(it, key=lambda e: e.name)
        except OSError as e:
            fehler.append('Ordner nicht lesbar: %s' % zeige(e))
            continue
        unterordner = []
        for e in eintraege:
            rel = rel_ordner + '/' + e.name if rel_ordner else e.name
            try:
                art = ist_verweis(e.path)
                if art:
                    verweise.append((rel, art) + verweis_ziel(e.path))
                elif e.is_dir(follow_symlinks=False):
                    unterordner.append(rel)
                elif e.is_file(follow_symlinks=False):
                    yield e.path, rel
            except OSError as err:
                fehler.append('nicht lesbar: %s (%s)' % (zeige(e.path), zeige(err)))
        stapel.extend(reversed(unterordner))


def ordner_hash(zeilen, verweise):
    """SHA-256 der sortierten Zeilen relpfad<TAB>sha256, Verweise als relpfad<TAB>art:ziel."""
    alle = list(zeilen) + ['%s\t%s:%s' % (rel, art, z) for rel, art, z, _ in verweise]
    return hashlib.sha256('\n'.join(sorted(alle)).encode('utf-8')).hexdigest()


def ordner_sha(ziel, fehler, verweise=None):
    """(Pruefsumme, Anzahl Dateien) fuer den Register-Abgleich ohne Scan. Aus einem .git-Ordner an der Wurzel
    zaehlen nur config, hooks und info; der Datenbestand aendert sich bei jedem Abruf."""
    if verweise is None:
        verweise = []
    zeilen = []
    anzahl = 0
    for pfad, rel in alle_dateien(ziel, fehler, verweise):
        anzahl += 1
        if git_datenbestand(rel):
            continue
        try:
            zeilen.append(rel + '\t' + datei_sha(pfad)[0])
        except OSError as e:
            fehler.append('nicht lesbar: %s (%s)' % (zeige(pfad), zeige(e)))
    return ordner_hash(zeilen, verweise), anzahl


# ---------------------------------------------------------------- Pruefregister (JSON)

REGISTER_STANDARD = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'pruefregister.json')
REGISTER_PFLICHT = ('datum', 'name', 'art', 'quelle', 'ampel', 'entscheidung')
REGISTER_FREI = ('sha256', 'sha256_kurz', 'bytes', 'befund', 'entscheidung_details')
AMPELN = ('GRUEN', 'GELB', 'ROT')
ENTSCHEIDUNGEN = ('offen', 'freigegeben', 'freigegeben-mit-rahmen', 'nur-entschaerfte-kopie', 'verworfen')
ARTEN = ('Datei', 'Ordner')


def register_lesen(text):
    """Liest pruefregister.json. Jeder Formfehler wirft ValueError (fuehrt zu Exit 4); nichts wird still
    uebersprungen. Eintraege mit sha256 (64 Hex) oder, nur fuer den Altbestand, sha256_kurz (8...8 Hex)."""
    try:
        daten = json.loads(text)
    except ValueError as e:
        raise ValueError('kein gueltiges JSON (%s)' % e)
    if not isinstance(daten, dict) or daten.get('format') != 1 or not isinstance(daten.get('eintraege'), list):
        raise ValueError('erwartet ein Objekt mit "format": 1 und "eintraege": [...]')
    fremd = set(daten) - {'format', 'hinweis', 'eintraege'}
    if fremd:
        raise ValueError('unbekannte Schluessel %s' % ', '.join(sorted(fremd)))
    eintraege = []
    for i, e in enumerate(daten['eintraege'], 1):
        if not isinstance(e, dict):
            raise ValueError('Eintrag %d ist kein Objekt' % i)
        fehlt = [f for f in REGISTER_PFLICHT if f not in e]
        if fehlt:
            raise ValueError('Eintrag %d: Feld fehlt (%s)' % (i, ', '.join(fehlt)))
        fremd = set(e) - set(REGISTER_PFLICHT) - set(REGISTER_FREI)
        if fremd:
            raise ValueError('Eintrag %d: unbekannte Felder (%s)' % (i, ', '.join(sorted(fremd))))
        if not all(isinstance(e[f], str) and e[f].strip() for f in REGISTER_PFLICHT):
            raise ValueError('Eintrag %d: Pflichtfelder muessen nichtleerer Text sein' % i)
        try:
            datetime.date.fromisoformat(e['datum'])
            if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', e['datum']):
                raise ValueError
        except ValueError:
            raise ValueError('Eintrag %d: Datum nicht im Format JJJJ-MM-TT' % i)
        for feld, werte in (('ampel', AMPELN), ('entscheidung', ENTSCHEIDUNGEN), ('art', ARTEN)):
            if e[feld] not in werte:
                raise ValueError('Eintrag %d: %s muss eins von %s sein' % (i, feld, ', '.join(werte)))
        if ('sha256' in e) == ('sha256_kurz' in e):
            raise ValueError('Eintrag %d: genau eins von sha256 und sha256_kurz' % i)
        if 'sha256' in e:
            if not (isinstance(e['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', e['sha256'])):
                raise ValueError('Eintrag %d: sha256 braucht 64 Hex-Zeichen (klein)' % i)
            anfang, ende = e['sha256'][:8], e['sha256'][-8:]
        else:
            m = re.fullmatch(r'([0-9a-f]{8})\.\.\.([0-9a-f]{8})', e['sha256_kurz']) if isinstance(e['sha256_kurz'], str) else None
            if not m:
                raise ValueError('Eintrag %d: sha256_kurz im Format 8 Hex ... 8 Hex' % i)
            anfang, ende = m.groups()
        eintraege.append({'datum': e['datum'], 'name': e['name'], 'art': e['art'], 'ampel': e['ampel'],
                          'entscheidung': e['entscheidung'], 'sha256': e.get('sha256'), 'anfang': anfang,
                          'ende': ende, 'altbestand': 'sha256_kurz' in e})
    return eintraege


def register_laden(register):
    """(eintraege, fehlertext)."""
    try:
        with open(register, encoding='utf-8') as f:
            return register_lesen(f.read()), None
    except OSError as e:
        return None, 'Register nicht lesbar: %s (%s)' % (zeige(register), zeige(e.strerror or e))
    except ValueError as e:
        return None, 'Register ungueltig: %s: %s' % (zeige(register), zeige(e))


def register_abgleich(eintraege, name, sha):
    """BEKANNT = gleiche Pruefsumme (auch unter anderem Namen; Altbestand nur 8...8 Zeichen), GEAENDERT = Name
    bekannt, Pruefsumme anders, NEU = weder noch. Zuerst zaehlt die Pruefsumme, der Name nur fuer GEAENDERT.
    Volle Pruefsumme geht vor Altbestand; bei mehreren Treffern gilt der letzte in der Datei, nicht der mit dem
    juengsten Datum."""
    sha = sha.lower()
    voll = [e for e in eintraege if e['sha256'] == sha]
    if voll:
        return 'BEKANNT', voll[-1]
    alt = [e for e in eintraege if e['altbestand'] and sha.startswith(e['anfang']) and sha.endswith(e['ende'])]
    if alt:
        return 'BEKANNT', alt[-1]
    gleichnamig = [e for e in eintraege if e['name'].lower() == name.lower()]
    if gleichnamig:
        return 'GEAENDERT', gleichnamig[-1]
    return 'NEU', None


def register_meldung(eintraege, name, sha):
    """Nur feste, gepruefte Felder; Name maskiert. Quelle und Befundtext erscheinen nie."""
    if eintraege is None:
        return 'Register: nicht verfuegbar, Abgleich entfaellt', 'NEU'
    status, e = register_abgleich(eintraege, name, sha)
    if status == 'BEKANNT':
        text = 'Register: BEKANNT, geprueft am %s als %s | Ampel %s | Entscheidung %s%s' % (
            e['datum'], zeige(e['name'])[:80], e['ampel'], e['entscheidung'],
            ' | Altbestand, nur 64 Bit verglichen' if e['altbestand'] else '')
    elif status == 'GEAENDERT':
        text = 'Register: GEAENDERT seit Pruefung am %s (dort %s...%s), gilt als ungeprueft' % (
            e['datum'], e['anfang'], e['ende'])
    else:
        text = 'Register: NEU, kein Eintrag'
    return text, status


def register_liste(register):
    eintraege, fehlertext = register_laden(register)
    if fehlertext:
        print('== FEHLER: %s ==' % fehlertext)
        return EXIT_UNVOLLSTAENDIG
    print('Pruefregister %s: %d Eintraege' % (zeige(register), len(eintraege)))
    print('Datum | Art | Name | Ampel | Entscheidung | SHA-256 gekuerzt')
    for e in eintraege:
        print('%s | %s | %s | %s | %s | %s...%s%s' % (e['datum'], e['art'], zeige(e['name'])[:80], e['ampel'],
                                                     e['entscheidung'], e['anfang'], e['ende'],
                                                     ' (Altbestand)' if e['altbestand'] else ''))
    return 0


# ---------------------------------------------------------------- Lauf und Ausgabe

AUFRUF = ('Aufruf: scan.py [--register <datei>] [--nur-register] [--erwartet <sha256>] [--bericht <datei>] '
          '<datei-oder-ordner> [...]\n        scan.py [--register <datei>] --register-liste')


def main(argv, version=None):
    version = tuple(version or sys.version_info[:2])
    if version < MINDEST_PYTHON:
        print('\n== FEHLER: Python %d.%d, scan.py braucht mindestens %d.%d (os.path.isjunction). '
              'Ergebnis unvollstaendig, Exit %d ==' % (version + MINDEST_PYTHON + (EXIT_UNVOLLSTAENDIG,)))
        return EXIT_UNVOLLSTAENDIG
    register = REGISTER_STANDARD
    nur_register = liste = False
    erwartet = bericht = None
    ziele = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ('--register', '--erwartet', '--bericht'):
            if i + 1 >= len(argv):
                print(AUFRUF)
                return EXIT_AUFRUF
            wert = argv[i + 1]
            if a == '--register':
                register = wert
            elif a == '--erwartet':
                erwartet = wert.lower()
            else:
                bericht = wert
            i += 2
            continue
        if a == '--nur-register':
            nur_register = True
        elif a == '--register-liste':
            liste = True
        elif a.startswith('--'):
            print('Unbekannter Schalter: %s\n%s' % (zeige(a), AUFRUF))
            return EXIT_AUFRUF
        else:
            ziele.append(a)
        i += 1
    if liste:
        if ziele:
            print(AUFRUF)
            return EXIT_AUFRUF
        return register_liste(register)
    if not ziele:
        print(AUFRUF)
        return EXIT_AUFRUF
    if erwartet is not None and (len(ziele) != 1 or not re.fullmatch(r'[0-9a-f]{64}', erwartet)):
        print('--erwartet braucht genau ein Ziel und 64 Hex-Zeichen\n%s' % AUFRUF)
        return EXIT_AUFRUF
    try:
        return lauf(ziele, register, nur_register, erwartet, bericht)
    except Exception as e:
        print('\n== FEHLER: Scan abgebrochen (%s: %s), Ergebnis unvollstaendig ==' % (type(e).__name__, zeige(e)))
        return EXIT_UNVOLLSTAENDIG


def neues_ziel(ziel):
    return {'anzeige': zeige(ziel), 'kopf': [], 'befunde': [], 'dateien': [], 'nicht_gescannt': [],
            'buendel': {}}


def befund_aufnehmen(z, gesamt, rel, b):
    gesamt[b[0]] += 1
    z['befunde'].append((rel,) + tuple(b))


def pruefsumme_vergleichen(z, ist, erwartet, fehler):
    if erwartet is None:
        return
    if ist == erwartet:
        z['kopf'].append('Abgleich mit --erwartet: gleich (Kopie entspricht dem Original)')
    else:
        z['kopf'].append('Abgleich mit --erwartet: ABWEICHUNG')
        fehler.append('Pruefsumme weicht von --erwartet ab: erwartet %s, ist %s' % (erwartet, ist))


def lauf(ziele, register, nur_register, erwartet=None, bericht=None):
    fehler = []
    eintraege, fehlertext = register_laden(register)
    if fehlertext:
        fehler.append(fehlertext)
        register_zeile = fehlertext
    else:
        register_zeile = 'Register: %s (%d Eintraege)' % (zeige(register), len(eintraege))
    gesamt = {ROT: 0, GELB: 0, INFO: 0}
    zaehler = {'gescannt': 0, 'nicht': 0, 'datenbestand': 0}
    unbekannt = 0
    erg = []
    for ziel in ziele:
        z = neues_ziel(ziel)
        erg.append(z)
        art = ist_verweis(ziel)
        if art:
            ziel_text, da = verweis_ziel(ziel)
            befund_aufnehmen(z, gesamt, '(Ziel selbst)', verweis_befunde([('(Ziel selbst)', art, ziel_text, da)])[0])
            fehler.append('Ziel ist ein Verweis (%s), der Inhalt dahinter ist nicht das Original: %s' % (art, zeige(ziel)))
            continue
        if not os.path.exists(ziel):
            fehler.append('Pfad nicht gefunden: %s' % zeige(ziel))
            z['kopf'].append('[FEHLER] Pfad nicht gefunden')
            continue
        ist_ordner = os.path.isdir(ziel)
        name = os.path.basename(os.path.normpath(ziel))
        if nur_register:
            if ist_ordner:
                verweise = []
                sha, anzahl = ordner_sha(ziel, fehler, verweise)
                z['kopf'].append('Ordner-SHA-256 %s' % sha)
                if verweise:
                    for b in verweis_befunde(verweise):
                        befund_aufnehmen(z, gesamt, '(Ordner)', b)
                    fehler.append('Verweis im Ordner %s: Abgleich nicht moeglich, eine Kopie wuerde dem Verweis folgen' % zeige(ziel))
                elif not anzahl:
                    fehler.append('keine Datei gefunden: %s' % zeige(ziel))
            else:
                try:
                    sha = datei_sha(ziel)[0]
                except OSError as e:
                    fehler.append('nicht lesbar: %s (%s)' % (zeige(ziel), zeige(e.strerror or e)))
                    continue
                z['kopf'].append('SHA-256 %s' % sha)
            text, status = register_meldung(eintraege, name, sha)
            unbekannt += status != 'BEKANNT'
            z['kopf'].append(text)
            pruefsumme_vergleichen(z, sha, erwartet, fehler)
            continue
        zeilen, verweise, liste = [], [], []
        for pfad, rel in alle_dateien(ziel, fehler, verweise):
            try:
                liste.append((rel, os.path.getsize(pfad)))
            except OSError:
                liste.append((rel, 0))
            if git_datenbestand(rel):
                zaehler['datenbestand'] += 1
                zaehler['nicht'] += 1
                continue
            try:
                kopf, befunde = scan_datei(pfad, rel)
            except OSError as e:
                fehler.append('nicht lesbar: %s (%s)' % (zeige(pfad), zeige(e.strerror or e)))
                continue
            zeilen.append(rel + '\t' + kopf['sha256'])
            befunde = name_befunde(rel) + befunde
            if kopf['gescannt']:
                zaehler['gescannt'] += 1
            else:
                zaehler['nicht'] += 1
                z['nicht_gescannt'].append(zeige(rel))
            z['dateien'].append((zeige(rel), kopf, befunde))
            nm = node_modules_pfad(rel)
            for b in befunde:
                if nm and b[0] != ROT:
                    gesamt[b[0]] += 1
                    schluessel = (b[0], b[1])
                    z['buendel'].setdefault(zeige(nm), {})
                    z['buendel'][zeige(nm)][schluessel] = z['buendel'][zeige(nm)].get(schluessel, 0) + 1
                else:
                    befund_aufnehmen(z, gesamt, zeige(rel), b)
        if not liste:
            fehler.append('keine Datei gefunden: %s' % zeige(ziel))
        for b in verweis_befunde(verweise) + ordner_befunde(liste):
            befund_aufnehmen(z, gesamt, '(Ordner)', b)
        if ist_ordner:
            sha = ordner_hash(zeilen, verweise)
            z['kopf'].append('Ordner-SHA-256 %s | %d Dateien' % (sha, len(liste)))
        elif z['dateien']:
            kopf = z['dateien'][0][1]
            sha = kopf['sha256']
            z['kopf'].append('SHA-256 %s | %d Bytes | %d Zeilen | BOM %s' % (
                sha, kopf['bytes'], kopf['zeilen'], 'ja' if kopf['bom'] else 'nein'))
        else:
            continue
        z['kopf'].append(register_meldung(eintraege, name, sha)[0])
        pruefsumme_vergleichen(z, sha, erwartet, fehler)

    if bericht:
        try:
            with open(bericht, 'w', encoding='utf-8', newline='\n') as f:
                f.write(vollbericht(register_zeile, erg))
        except OSError as e:
            fehler.append('Bericht nicht schreibbar: %s (%s)' % (zeige(bericht), zeige(e.strerror or e)))
    fehler = list(dict.fromkeys(fehler))  # Pruefsumme und Scan melden dieselbe Datei
    if fehler:
        code = EXIT_UNVOLLSTAENDIG
    elif nur_register:
        code = 3 if unbekannt else 0
    elif gesamt[ROT]:
        code = 2
    elif gesamt[GELB] or zaehler['nicht']:
        code = 1
    else:
        code = 0
    if nur_register:
        schluss = '== Register-Abgleich: %d von %d Zielen neu oder geaendert | Fehler %d | Exit %d ==' % (
            unbekannt, len(ziele), len(fehler), code)
    else:
        schluss = ('== Ergebnis: ROT %d | GELB %d | INFO %d | als Text gescannt %d | nicht gescannt %d | Fehler %d ==\n'
                   '== Exit %d%s ==' % (gesamt[ROT], gesamt[GELB], gesamt[INFO], zaehler['gescannt'], zaehler['nicht'],
                                        len(fehler), code, ' | davon .git-Datenbestand %d' % zaehler['datenbestand']
                                        if zaehler['datenbestand'] else ''))
    print(register_zeile)
    print(schluss)
    if fehler:
        print('== FEHLER (%d): Ergebnis unvollstaendig, nie als sauber werten ==' % len(fehler))
        for f in fehler:
            print('  %s' % f)
    kurzausgabe(erg)
    if bericht and not any(f.startswith('Bericht nicht schreibbar') for f in fehler):
        print('\nVollbericht mit Zeilenauszuegen: %s' % zeige(bericht))
    print('\n' + schluss)
    return code


def zeilennummern(nummern):
    n = sorted({x for x in nummern if x})
    if not n:
        return ''
    text = ', '.join(str(x) for x in n[:MAX_ZEILENNUMMERN])
    return ' (Z. %s%s)' % (text, ', ...' if len(n) > MAX_ZEILENNUMMERN else '')


def kurzausgabe(erg):
    """Fuer den Agenten: je Ziel Kopf, ROT einzeln ohne Zeilenauszug, GELB je Datei und Kategorie gebuendelt,
    INFO nur gezaehlt. Laenge begrenzt, Rest steht im Vollbericht."""
    rot_zeilen = gelb_zeilen = 0
    for z in erg:
        print('\n## %s' % z['anzeige'])
        for zeile in z['kopf']:
            print('  %s' % zeile)
        rot = [b for b in z['befunde'] if b[1] == ROT]
        if rot:
            print('  ROT (%d):' % len(rot))
        for rel, stufe, kat, nr, detail, _ in rot:
            if rot_zeilen >= MAX_ROT_ZEILEN:
                print('  ... weitere ROT nur im Vollbericht (--bericht)')
                break
            rot_zeilen += 1
            print('  [ROT] %s%s %s: %s' % (rel, ':Z%d' % nr if nr else '', kat, zeige(detail)[:100]))
        # GELB ohne Zeilennummer (Datei- und Ordnerbefunde, feste Texte mit maskierten Pfaden) einzeln mit Erklaerung,
        # GELB aus Textzeilen nur gebuendelt, damit kein Zeileninhalt in die Ausgabe gelangt
        einzeln = [b for b in z['befunde'] if b[1] == GELB and not b[3]]
        gruppen = {}
        for rel, stufe, kat, nr, _, _ in z['befunde']:
            if stufe == GELB and nr:
                gruppen.setdefault((rel, kat), []).append(nr)
        if gruppen or einzeln:
            print('  GELB (%d Befunde, %d Datei-/Ordnerbefunde und %d Gruppen):' % (
                sum(len(v) for v in gruppen.values()) + len(einzeln), len(einzeln), len(gruppen)))
        for rel, stufe, kat, nr, detail, _ in einzeln:
            if gelb_zeilen >= MAX_GELB_ZEILEN:
                break
            gelb_zeilen += 1
            print('  [GELB] %s %s: %s' % (rel, kat, zeige(detail)[:100]))
        for (rel, kat), nummern in sorted(gruppen.items()):
            if gelb_zeilen >= MAX_GELB_ZEILEN:
                print('  ... weitere GELB-Gruppen nur im Vollbericht (--bericht)')
                break
            gelb_zeilen += 1
            print('  [GELB] %s: %s x%d%s' % (rel, kat, len(nummern), zeilennummern(nummern)))
        info = {}
        for _, stufe, kat, *_ in z['befunde']:
            if stufe == INFO:
                info[kat] = info.get(kat, 0) + 1
        if info:
            print('  INFO: %s (Einzelheiten und URLs im Vollbericht)' % ', '.join(
                '%s x%d' % (k, n) for k, n in sorted(info.items())))
        for nm in sorted(z['buendel']):
            print('  Gebuendelt %s: %s' % (nm, ', '.join('%s %s x%d' % (s, k, n) for (s, k), n in sorted(z['buendel'][nm].items()))))
        if z['nicht_gescannt']:
            print('  Nicht als Text gescannt (%d): %s%s' % (len(z['nicht_gescannt']), ', '.join(z['nicht_gescannt'][:10]),
                                                           ' ...' if len(z['nicht_gescannt']) > 10 else ''))


def vollbericht(register_zeile, erg):
    """Fuer den Menschen: alle Befunde je Datei mit maskiertem Zeilenauszug."""
    aus = [register_zeile]
    for z in erg:
        aus.append('\n## %s' % z['anzeige'])
        aus += ['  %s' % zeile for zeile in z['kopf']]
        for rel, kopf, befunde in z['dateien']:
            aus.append('\n### %s' % rel)
            aus.append('  SHA-256 %s | %d Bytes | %d Zeilen | BOM %s' % (
                kopf['sha256'], kopf['bytes'], kopf['zeilen'], 'ja' if kopf['bom'] else 'nein'))
            if not befunde:
                aus.append('  keine Befunde')
            for stufe in (ROT, GELB, INFO):
                for s, kat, nr, detail, auszug in befunde:
                    if s == stufe:
                        aus.append('  [%s] %s %s: %s' % (s, 'Z%d' % nr if nr else 'Datei', kat, zeige(detail)))
                        if auszug:
                            aus.append('         | %s' % auszug)
        ordner = [b for b in z['befunde'] if b[0] in ('(Ordner)', '(Ziel selbst)')]
        if ordner:
            aus.append('\n### Verweise und mitgelieferte Ordner')
            aus += ['  [%s] %s: %s' % (s, kat, zeige(d)) for _, s, kat, _, d, _ in ordner]
    return '\n'.join(aus) + '\n'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
