# Z8-DBBLOB — Binär-Dateien als verschlüsselte Blobs (Dateimanager-Kern)

Aufsatz auf die **dbnode-Engine** (Z8DBNODE): Blobs (Screenshots, Aufnahmen,
beliebige Binärdaten) werden verschlüsselt über das bestehende
`StorageBackend` (S3Backend / FsBackend / DummyBackend) verwaltet. Die
Datenbank hält **nur die Metazeile** — Rohdaten liegen NIE in SQLite
(DECKEL-Regel bleibt Gesetz).

## Bausteine
| Modul | Aufgabe |
|---|---|
| `dbnode/blob.rs` | `blob_put_*`, `blob_get_*`, `blob_list`, `blob_delete`, `blob_gc` |
| `dbnode/blob_io.rs` | Part-Chiffre (AES-256-GCM, HKDF je Part), Key-Hülle, Upload-Schleife |
| `dbnode/blob_meta.rs` | Metazeile `linefs_blobs` (Name, MIME, Größe, SHA256, Key-Ref, epoch) |
| `dbnode/blob_stream.rs` / `blob_playback.rs` | Zeit-Chunk-Aufnahmen + Playlist |
| `dbnode/blob_export*.rs` | PQC-Container (Export an Dritte) |

## Metazeile = Zeile
Jeder Blob ist eine Zeile in `linefs_blobs` und läuft durch den normalen
WAL-Schreibpfad (Reservierungspflicht, Ein-Schreiber, Epochen):

```
blob_id, name, mime, groesse, sha256_klartext, content_key_huellereferenz,
storage_uri, epoch, owner, parts, session_id, chunk_index, dauer_ms, created_at
```

`epoch` ist die WAL-Nummer des Inserts; `list` liefert die Dateimanager-
Felder `{blob_id, name, mime, groesse, epoch, owner, parts}`.

## Verschlüsselung
- Je Blob ein **zufälliger Content-Key (32 B)**.
- Datei wird in **1-MiB-Parts** gestreamt; Part-Key =
  `HKDF-SHA256(Content-Key, "ctx|p<i>")`, AES-256-GCM mit AAD
  `ctx|p<i>`. S3/Fs sehen ausschließlich Chiffre.
- Content-Key wird mit dem **DB-Schlüssel** (HKDF aus dem Masterkey,
  AES-256-GCM) versiegelt und in der Metazeile abgelegt. Ohne Masterkey
  öffnet keine Hülle.
- Part-Reihenfolge/Manipulation wird zusätzlich über `sha256_klartext`
  und die AAD erkannt.

## Storage-URI / Reihenfolge
- Objekte: `blobs/<db>/<blob_id>/<part:08>.part`.
- Upload: Parts zuerst, **Manifest/Metazeile erst danach** → kein Halb-Blob.
- Delete: **erst** Metazeile (WAL), **dann** Backend-Objekt. Crash
  dazwischen erzeugt ein harmloses verschlüsseltes Orphan; `blob_gc`
  gleicht Backend-Liste gegen Metazeilen ab und entfernt Differenzen.

## CHUNK-STREAMING (HLS-Muster)
Lange Medien werden nie am Stück gehalten:

1. `blob_session_begin(db, session, owner, mime)` → `session_id`,
   ein Session-Content-Key (versiegelt in `linefs_blob_sessions`).
2. `blob_session_append(db, session, sid, daten, dauer_ms)` → ein
   **unveränderlicher Chunk-Blob**, Key = `HKDF(Session-Key, chunk_index)`
   (keine eigene Key-Hülle je Chunk). Chunk sofort hochgeladen.
3. `blob_session_finish` setzt `gesamt_sha256` (Playlist-Wahrheit).
4. `blob_session_get_*` lädt Chunks in Manifest-Reihenfolge, entschlüsselt
   on-the-fly und prüft Chunk- und Gesamt-SHA256.

Manifest-Zeile: `{session_id, chunk_ids[], gesamt_sha256, dauer_ms,
session_key_huellereferenz, epoch, owner, mime}`. Chunk-Tausch oder
Reihenfolge-Manipulation → `BLOB_SEAL`/`BLOB_INTEGRITY`. Kurz-Sessions
(< Chunk-Größe) = genau ein Chunk.

## PQC-Container (Export)
Eine Datei = `{format, manifest{meta, sha256, chunks[]}, key_box}` —
funktional eine PQC-Zip. Jeder Export nutzt einen **frischen eigenen
Content-Key** (nie den DB-Master). Key-Box-Pyramide, Default verschlüsselt:
1. **PQC**: v3-hybrid (P-256 + ML-KEM-1024) an den Empfänger-Pubkey.
2. **Passwort**: Argon2id ∥ ML-KEM — Passwort entsperrt ECC-Privatekey und
   ML-KEM-dk der v3-Box; Mindest-Entropie erzwungen (`WEAK_PASSWORD`).
3. **Klartext** nur mit explizitem Bestätigungsschritt (`CONFIRM_REQUIRED`).

Falscher Empfänger-Key / falsches Passwort → Fehler. Keine Presigned-URLs
und kein Klartext-Zugriff auf S3: alles läuft durch die Engine.

## Z8-Nodes (Kategorie data)
`blob-put` (Datei-Pfad oder base64), `blob-get` (Datei-Ziel oder base64),
`blob-list`, `blob-delete`. Dünn, Engine dahinter; `blob-delete` ohne
Reservierung → `NOT_RESERVED`. `blob-get` fremde/nicht offene `db_id` →
`NOT_OPEN` (error-Port).

## MCP `z8_db`
Neue Aktionen: `blob_put`, `blob_get`, `blob_list`, `blob_delete` über
`/data/z8run/bin/z8-dbnode` (One-Shot-CLI, dieselbe Engine). Antworten
enthalten nie den Masterkey; `blob_get` liefert Klartext nur an den
Aufrufer (Datei-Ziel oder base64).

## Messwerte (Rohlogs in `/data/z8run-test/verify-logs/z8-dbblob/`)
- 100-MB-Upload/Download: RSS-Anstieg **2 764 KiB / 2 112 KiB** über
  Grundlast (Ziel < 10 MB) — feste 1-MiB-Parts, kein Voll-RAM.
- 12-Chunk-Aufnahme: RSS flach, Wiedergabe-SHA256 == Original;
  Manifest 12 Chunks, 360 000 ms.
- Restart: Blob-Meta sofort aus DB/WAL da; **0 Blob-Reads** beim Start,
  erst der erste `get` lädt das Backend-Objekt.
- Echtes DanubeData-S3: 3 Größen × 2 DBs × 2 Cluster, Downloads quer,
  Cleanup `rest=0` (je Prefix 228 Objekte entfernt).
