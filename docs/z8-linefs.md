# Z8-LINEFS — Zeilen-Dateisystem, Ordner und Dedup im DB-Node

Aufsatz auf **Z8DBNODE/Z8DBBLOB**: Jede geöffnete DB hat zusätzlich zur
Blob-Welt eine **Zeilen-Welt** (Editor/LineFS-Kern), einen **Ordner-Baum**
und eine **Content-Dedup-Index-Tabelle**. Wahrheit ist immer die DB
(SQLCipher), nie ein Dateiformat und nie ein gespeicherter Pfad.

## Herkunft / Lizenz
Der Kern (zeilen.rs, scheide.rs, Commit-Planung, Hashkette) ist ein
**Modulimport** des CE-Geschenks (`linefs-kern`, AGPL-3.0 +
ArtCraft-Exception). Urheberrecht liegt bei uns; Eigen-Nutzung im
Closed-Source-Produkt ist als Rechteinhaber legal (Dual-Use). Das
CE-REPO bleibt unangetastet. Portiert nach
`crates/z8run-core/src/dbnode/linefs_rows/` — **kein path-dep** (kein
absoluter Dev-Pfad, kein eingefrorenes CE-Schema).

Bewusste Adaptionen: (1) die 205er-**Policy** ist Konfig, die
physikalische Seitengroesse bleibt 205; (2) `art` bleibt
schema-kompatibel, die Code/Doku-Sonderbehandlung ist per Default AUS;
(3) kein `binaer_s3`/`Secret.db` — Binär läuft einheitlich über
`linefs_blobs`.

## Tabellen
| Tabelle | Inhalt |
|---|---|
| `dateien` | Name, art, ordner_id, status, fassung, hashkette, binaer_blob_id/sha |
| `seiten` / `s_{datei_id}_{seite}` | physische Seiten (205 Zeilen) + Segmente |
| `zeilen_epochen` | JEDE Fassung jeder Zeile (WORM), Hashkette, Urheber, ts |
| `ordner` | Baum: id, eltern_id, name (Wahrheit); Pfad nur gerenderte Sicht |
| `linefs_blobs` | Blob-Metazeile (Chiffre-Parts im StorageBackend) |
| `linefs_blobhash` | Dedup: sha256 → storage_uri, refcount, groesse |

## Befehlsmatrix (Endpoint-Übersicht)
Alle Befehle laufen über `DbNodeCommand::Linefs` (Engine-API) und den
MCP-Aktionen `linefs_*` / `ordner_*`. `R` = readonly ohne Reservierung,
`W` = Ein-Schreiber (Reservierungspflicht).

| Aktion | Typ | Verhalten |
|---|---|---|
| `LinefsAnlegen` | W | Text → dateien+seiten+zeilen_epochen (Fassung 1); DECKEL bei ungültigem UTF-8/Null-Byte |
| `LinefsOeffnen` | W | Session im RAM; Basis-Fassung für den Editor |
| `LinefsLesen` | R | Bereich als Zeilen mit Original-Zeilenenden |
| `LinefsZeileSetzen` | W* | Inhalt neue Fassung, Identität (schluessel) bleibt |
| `LinefsEinfuegen` | W* | lückenlose Neu-Nummerierung, Naht-Regel (Nachbar-Ende) |
| `LinefsZeileLoeschen` | W* | Grabmal; Geschichte behält alles |
| `LinefsSuchen` | R | byte-exakter Teilstring, keine Normalisierung |
| `LinefsErsetzen` | W* | alle byte-exakten Treffer der Session |
| `LinefsSpeichern` | R | DECKEL-Prüfung des gerenderten Stands, kein Commit |
| `LinefsSchliessen` | W | **COMMIT**: EINE Transaktion + EIN WAL-Objekt (`art:linefs`) |
| `LinefsRendere` | R | byte-identischer Roundtrip |
| `LinefsSeiten` | R | Seiten + Zeilenzahl |
| `LinefsHistorie` | R | alle Fassungen je Zeile (inkl. Grabmal) |
| `LinefsStandZuZeitpunkt` | R | Zeitmaschine: neueste Fassung ≤ X je Zeile |
| `LinefsUmbenennen` | W | nur Namens-Mapping, Zeilen/Epochen unberührt |
| `LinefsKettePruefen` | R | SHA256-Kette lückenlos nachrechnen (Manipulation = rot) |
| `LinefsRenderFuerProzess` | R | temporäre 0700/0600-Kopie; `LinefsProzessEnde` räumt sie |
| `LinefsBinaerHochladen` | W | Blob über `linefs_blobs` (kein binaer_s3) |
| `LinefsBinaerZeigen` / `Holen` | R | Metazeile / Klartext mit SHA-Beweis |
| `LinefsUebergangZuBinaer/Text` | W | bewusster, epochen-belegter Seitenwechsel |
| `OrdnerAnlegen` | W | Name/Tiefe geprüft (max 32 Ebenen, 255 Zeichen) |
| `OrdnerVerschieben` | W | Zyklus-Verbot, Tiefen-Grenze, EINE Transaktion |
| `OrdnerUmbenennen` | W | auch mit Kindern EINE Transaktion |
| `OrdnerListen` | R | Baum mit gerenderten Pfaden |
| `OrdnerPfadAufloesen` | R | `a/b/c.txt` → Datei |

`W*` = Session-Änderung im RAM, persistiert erst bei `LinefsSchliessen`.

## WAL
Zeilen-/Ordner-Commits sind **EINE WAL-Nummer** mit `art = "linefs"` und
einer Aktionsliste (`ops`) — derselbe Ein-Schreiber-Pfad, dieselbe
`prev_hash`-Kette wie SQL-Writes. Ein Commit = EINE DB-Transaktion;
`_z8_line_epochs` bleibt lückenlos. Snapshot/Restore wendet `ops`
identisch an.

## Konfiguration
| Feld | Default | Wirkung |
|---|---|---|
| `DbNodeConfig::zeilen_limit` (`Z8_LINEFS_ZEILEN_LIMIT`) | 0 | 0 = unbegrenzt; n = harte Grenze für neue Commits |
| `DbNodeConfig::code_docu_unterscheidung` (`Z8_LINEFS_CODE_DOCU`) | false | false = keine Sonderbehandlung; true = `code` begrenzt, `dokument` auto-gepagert |

Kern-Physik (Epochen, WORM, DECKEL, Kette, 205er-Seiten) ist nicht
konfigurierbar.

## Ordner-Modell
Der Baum (`ordner.eltern_id`) ist die Wahrheit. Pfade werden bei Bedarf
aus dem Baum gerendert und nie gespeichert. Integritätsprüfung vor jedem
Zeilen-/Ordner-Commit: keine verwaisten `dateien.ordner_id`, keine
fehlenden Eltern, keine Zyklen.

## Dedup
`LinefsBinaerHochladen`/`blob_put` berechnet **streamend** sha256 über
eine Temp-Datei (RSS flach) und prüft `linefs_blobhash`:
- Treffer: **kein Upload**, neue Metazeile mit gleicher `storage_uri`,
  `refcount + 1`.
- Miss: Parts hochladen, Metazeile, dann Index-Zeile. Race: beide laden
  hoch, einer gewinnt den UNIQUE-Insert; der Verlierer biegt seine
  Metazeile auf den Gewinner um, seine Parts bleiben Orphan → `blob_gc`.
- Delete: **Meta zuerst**, dann `refcount - 1`; erst bei 0 Backend-Objekt
  und Index-Zeile weg.

Alt-Bestand ohne Index-Zeile bleibt lesbar und löschbar; er wird NICHT
nachgerüstet (Treffer auf Altdaten bewusst verpasst).

## Z8-Nodes (Kategorie `files`)
`linefs-open`, `linefs-read`, `linefs-write` (setzen/einfuegen/loeschen),
`linefs-close`, `linefs-list`, `ordner-list`, `ordner-pfad`. Dünn, Engine
dahinter, error-Port bei Fehlern, Masterkey wird aus Antworten gestrippt.
Demo-Flow: `crates/z8run-core/tests/fixtures/db-linefs-export.flow.json`
(Positionen gesetzt, sauberes Layout).

## MCP `z8_db`
Über `/data/z8run/bin/z8-dbnode` (One-Shot, dieselbe Engine):
`linefs_anlegen|linefs_open|linefs_read|linefs_write|linefs_insert|
linefs_delete|linefs_close|linefs_render|linefs_pages|linefs_history|
linefs_verify|linefs_rename|linefs_blob_put|linefs_blob_get|
linefs_blob_show` sowie `ordner_anlegen|ordner_verschieben|
ordner_umbenennen|ordner_listen|ordner_pfad_aufloesen`.
`action="linefs_ops"` führt eine `ops`-Liste (open/write/close) in EINEM
Prozess aus. Antworten enthalten nie den Masterkey.

## Beweise
Rohlogs: `/data/z8run-test/verify-logs/z8-linefs/` (S1-Roundtrip/Segmente/
Kette, S2-Ordner, S3-Limit/Dedup/Race/RSS, S4 echtes S3 mit
`dbs/test-linefs/` und `rest=0`, Nodes, Export CLI+Server, MCP, Install).
