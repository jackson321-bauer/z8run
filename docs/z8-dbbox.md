# Z8-DB-NODE (dbbox)

Der DB-Node ist eine **eigene Rust-Engine-Bibliothek** in
`crates/z8run-core/src/dbnode/`. Sie enthält **keinen z8-Code** (keine
Flow-/Engine-/Node-Typen) — sie kennt nur std, SQLite, Krypto und den
Storage-Trait. Die z8-Nodes (`db-open`, `db-query`, `db-write`,
`db-schema`, `db-status`, `db-sync`) sind dünne Wrapper:
Config/Payload rein, Engine rein, Message raus. SQL-String-Logik lebt
NICHT im Flow.

## Kern

- `DbNode` verwaltet N Datenbanken über M Cluster. Je DB: eigene
  Key-Hülle, eigener Reservierungs-/Schreibzustand, eigener WAL-Strom,
  eigenes RAM-Budget. Kein globaler Modus, keine Querschlüssel (FEST 13).
- **Masterkey kommt von außen**: `DbNode::open_db(id, master_key, cluster)`.
  Pro DB wird `db_key = HKDF-SHA256(master, db_id)` abgeleitet, in einer
  `KeyEnvelope` gehalten (mlock-Versuch, `zeroize` bei Drop).
- **Ein-Schreiber je DB**: Zustände `frei → reserviert(session) →
  schreibend`. `write` ohne Reservierung = `NOT_RESERVED`, zweite
  Reservierung = `BUSY`, `release` nur durch den Besitzer. Verschiedene
  DBs schreiben parallel; Lesen ist immer parallel (eigene Readonly-
  Verbindung, `PRAGMA query_only=ON`, WAL-Snapshot).
- **RAM-Budget je DB** ist real: `ram_budget_per_db` setzt den
  SQLite-Page-Cache (`PRAGMA cache_size=-<KiB>`), kein totes Config-Feld.
- **Warteschlange ist DB-Node-Sache**: je DB eine FIFO-
  `tokio::sync::Mutex`-Warteschlange mit `write_timeout` (fail-fast
  `TIMEOUT`). Der Proxy stellt nur Anfragen.

## SQLCipher + vec + FTS5

- `rusqlite 0.32.1` mit `bundled-sqlcipher-vendored-openssl` + `backup`.
  Grund für 0.32 statt 0.31: der Workspace nutzt bereits
  `libsqlite3-sys 0.30.1` (sqlx + SQLCipher). 0.31 verlangt 0.28 →
  zwei Pakete mit `links="sqlite3"` = harter Buildfehler. 0.32.1 nutzt
  denselben Versionsstrang (EIN SQLite im Produkt).
- **sqlite-vec v0.1.9 EINGEBRANNT**: `vendor/sqlite-vec.c` + `.h`,
  SHA256 `ba081a47fa02eadc3cf6b16c314b695b84081269349aac722b4efa338fe8fd85`,
  per `build.rs` mit `-DSQLITE_CORE` in den Bundled-Build kompiliert.
  Registrierung über `sqlite3_auto_extension` — **nicht** über
  `load_extension`; das Cargo-Feature ist nicht aktiviert. Beweis:
  `vec_version()` + `CREATE VIRTUAL TABLE … USING vec0(...)` unter
  SQLCipher ohne je aktivierten Loader (`s1-unit.log`).
- FTS5 ist über die Bundled-Defines (`SQLITE_ENABLE_FTS5`) verfügbar;
  `sqlite_compileoption_used('ENABLE_FTS5') = 1` ist getestet.

## WAL-Strom (drei Ebenen getrennt)

1. **LineFS intern**: Zeilen-Epochen in `_z8_line_epochs` (eine Zeile je
   WAL-Nummer, lückenlos), 205-Zeilen-Kante, DECKEL-Regel (Null-Byte
   oder >205 Zeilen = `DECKEL`, Commit abgelehnt).
2. **WAL-Strom = geschriebene Dateien**: je Änderung ein Objekt
   `wal/<db>/<nr:08>.json` mit `{nr, prev_hash, db, seal, hash}`. Die
   Nutzlast `{sql, params, ts}` ist AES-256-GCM-verschlüsselt, die
   HMAC-SHA256-Signatur bindet `db|nr|prev_hash`. Hash-Kette lückenlos.
   Reihenfolge: **zuerst Cloud** (Storage/Quorum), dann lokal. Fällt der
   Storage aus, bleibt das WAL lokal erhalten (`wal_pending`) und
   `wal-sync` holt es nach — kein Datenverlust.
3. **SQLite `journal_mode=WAL`** ist reine Engine-Technik für paralleles
   Lesen während des Schreibens (Innenleben, nicht der WAL-Strom).

Snapshots (64 WALs oder 1 h) sind eine SQLCipher-verschlüsselte Kopie der
DB-Datei (`snap/<db>/<nr>.db` + **versiegeltes/signiertes** Meta
`<nr>.meta` mit Kettenstand). Restart: gültiger
lokaler Stand → nur der fehlende WAL-Schwanz wird gezogen; ohne lokalen
Stand → Snapshot + WALs ab `snap+1` (Verhalten wie
`wal_restart_sim.py`). Zähler `remote_wal_downloaded` beweist es.
**Idempotenz**: `_z8_line_epochs` ist die Wahrheit — ein WAL, dessen
Epoche bereits existiert, wird beim Restart NICHT erneut angewandt
(Crash zwischen lokalem Commit und `state.json`). Fehlgeschlagenes SQL
wird vor jedem Cloud-Upload erkannt (ROLLBACK), hinterlässt also kein
totes Cloud-WAL. Beides ist als Regressionstest bewiesen
(`s1-regression.log`).

## Storage-Adapter

`StorageBackend { read, write, list, delete }`:

- `FsBackend` (std::fs, Pfad-Traversal geschützt),
- `S3Backend` (kv-store SigV4, wiederverwendet, kein Provider-SDK),
- `DummyBackend` (In-Memory, `set_online(false)` für den Ausfallbeweis).

OPFS/WASM dockt später am selben Trait an (eigener Folgeplan) — das
`DummyBackend` ist der Nahtbeweis, dass der Trait target-neutral ist.

## Nachrichten-Interface (natürlich, kein HTTP)

`DbNodeCommand` / `DbNodeEvent` (serde) über lokale `tokio::mpsc`:

```
OpenDb{db_id, master_key_b64, cluster}   CloseDb
Reserve / Release                         Write{sql, params, session}
Query{sql, params, readonly}              WalSync / Status / Schema
Event: Ok | WriteOk | Rows | WalProgress | Status | Schema | Error{code}
```

`Query` ist hart readonly: `readonly=false` wird mit `READONLY`
abgewiesen (kein versehentlicher Write über den Lese-Pfad). Beweis:
`msg`-Test sendet Commands über den Kanal und prüft Events.

## Nodes (dünn, Kategorie data, eigene Farbe `#0E7490`)

| Node | Config | Output |
|------|--------|--------|
| `db-open` | `dbId`, `clusterId`, `adapter` (fs/s3), `localDir`, `storageRoot`, `bucket`, `prefix`, `masterKeyPath` | `db_status` |
| `db-query` | `dbId`, `sql`, `paramsPath` | `columns`, `rows` |
| `db-write` | `dbId`, `sql`, `paramsPath`, `sessionPath`, `autoReserve` | `rowsAffected`, `walNr` |
| `db-schema` | `dbId` | `tables` (EN) + `tabellen` (FEST-Felder) |
| `db-status` | `dbId` (leer = alle) | `dbs` |
| `db-sync` | `dbId` | `progress` |

Payloads werden **gemerged**, nicht ersetzt: `req`, `params` und
`session_id` bleiben für nachfolgende Nodes erhalten. Der Masterkey wird
von **jedem** DB-Node aus dem Payload entfernt (bekannte Pfade
`master_key_b64`, `req.body.master_key_b64`, `master`,
`req.body.master`; `db-open` zusätzlich den konfigurierten
`masterKeyPath`) — er erscheint nie in Antworten oder Logs. `clusterRef`
ist ein Alias für `clusterId`. Fehler gehen auf den `error`-Port
(`{status: 400, code, error}`).

## Dokumentierte Abweichungen

- **rusqlite 0.32.1 statt 0.31** (Plan): 0.31 verlangt libsqlite3-sys 0.28,
  der Workspace nutzt bereits 0.30.1 (sqlx) → zwei `links="sqlite3"` =
  Buildfehler. 0.32.1 teilt denselben Versionsstrang.
- **S3-Multi-Test mit EINEM Dev-Key** statt drei scoped Keys: Für
  `dbs/test-a|b|c/` standen keine drei scoped DanubeData-Keys bereit; es
  wird derselbe Dev-Key mit drei getrennten Präfixen benutzt, fremde
  Präfixe (`sim2/`, `kronvault/`) werden nicht berührt. Die Engine
  unterstützt je Cluster eigene Keys (`Adapter::S3` je ClusterConfig).
- **WAL-Versiegelung** nutzt AES-256-GCM + HKDF + HMAC direkt (dieselben
  Primitive wie `kette`/`umschlag`) statt der Passwort-Box
  (`passbox_siegel`), weil Argon2id pro WAL-Write für einen
  Hochfrequenz-Strom ungeeignet ist. Kein neuer Krypto-Stack.
- **Crash-Fenster**: zwischen lokalem COMMIT und `state.json` bleibt ein
  schmales Fenster; die Epochen-Prüfung verhindert Doppelanwendung. Bei
  fehlgeschlagenem Upload und Crash vor dem lokalen WAL-File kann ein
  kalter Client die letzte Änderung erst über den nächsten Snapshot
  sehen (DB-Daten sind lokal vorhanden); dokumentiertes Restrisiko.

## Beweise (Rohlogs)

`/data/z8run-test/verify-logs/z8-dbbox/`:

- `s1-unit.log` — vec/FTS5/Reservierung/parallel/WAL/Restart/Epochen.
- `s2-flow.log` — unix-in POST /dbschema → db-open → db-write →
  db-schema (Roh-JSON), Negativ ohne Reservierung, parallel Read/Write.
- `s3-cluster.log` — 3 echte S3-Test-Prefixe (`dbs/test-a|b|c/`), WAL-
  Upload je Prefix gelistet, Prefixe wieder geleert.
- `s3-schema5.log` — ein Flow, 5 verbundene DBs, Schema-Antwort.
- `s4-export-cli.log` / `s4-export-server.log` — z8-export CLI+Server
  (open/write/read/sync, kein Masterkey in Antwort).
- `s4-export-tree.log` — `cargo tree`: kv-store/kv-login als path-deps;
  `grep "fn process"` im Export leer.
- `s4-offline.log` — Write überlebt Storage-Ausfall, `wal-sync` holt nach.
- `s1-regression.log` — Audit-BF-1 (stale state → keine Doppelanwendung)
  und BF-2 (fehlgeschlagenes SQL → kein Cloud-WAL, Reopen ok).
- `s4-ram.log` — RSS leer **4.77 MB**, 1 DB 9.03 MB, 5 DBs 9.50 MB,
  je weitere DB 0.12 MB (Ziel: Grundlast <10 MB, je DB <5 MB — erfüllt).
  Der Boden kommt aus bundled SQLCipher+OpenSSL und ist gemessen, keine
  Ausrede.

## MCP

`z8_db(action=open|query|write|schema|status|sync, db_id,
master_key_b64, sql, params, …)` ruft `/data/z8run/bin/z8-dbnode`
(One-Shot-CLI über dieselbe Engine). Antworten enthalten keinen
Masterkey. Quelle: `bins/z8-export/mcp/z8_db_run.py`, Beweis:
`s5-mcp-e2e.log`.
