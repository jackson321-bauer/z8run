# z8-proxy3b — Browser-Kern komplett

Stand: 01.11.2026. Bauplan: `bauplan-z8-proxy3b.md`.

## Feature-Split-Map (EIN Code, zwei Zielbilder)

`z8run-core` hat das Feature `native` (Default an).

| Baustein | nativ | Browser (wasm32) |
|---|---|---|
| `engine`, `flow`, `nodes`-Logik | ja | ja |
| `dbnode`-Native-Implementierung (sqlx/rusqlite/std::fs) | ja (`native`) | nein |
| `dbnode_contract_types` (DTOs, Status, Config) | ja | **ja** (geteilt) |
| `dbnode_contract_storage::StorageBackend` (Trait) | ja | **ja** (geteilt) |
| UDS/udsv3/systemd/egress/ram | ja (`native`) | nein |
| `proxy-kern` (Token/Session/App/Prompt/OTel) | ja | **ja** (identisch) |
| DB-Adapter | `FsBackend`/`S3Backend` | `BrowserDbPort` (SQLite+vec wasm) |
| Blob-Adapter | `FsBackend`/`S3Backend` | `OpfsBackend` am selben Trait |
| App-Laufzeit | Wasmtime | wasmi (portable-dispatch) |

Dual-Compile-Beweis:
```
cargo check -p z8run-core --target wasm32-unknown-unknown --no-default-features
cargo check -p z8run-core            # nativ, Default-Feature native
```

**Abgrenzung:** Der native `dbnode`-Kern (Restore/WAL/SQLite-Verbindung)
bleibt nativ-only, weil sqlx/rusqlite auf `wasm32-unknown-unknown` nicht
laufen. Geteilt sind die Verträge (Typen + Storage-Naht); die Browser-
Implementierung nutzt dieselbe Naht mit SQLite-im-WASM. Kein Code-Fork:
die Vertragsdateien sind für beide Ziele dieselben.

## OPFS-Schichten (getrennt)

- **DB-Weg:** SQLite+vec im WASM-RAM; nach jedem Write `serialize` →
  Z8FC1 (AES-256-GCM/HKDF, Schlüssel = HKDF-SHA256(master, salt
  `z8-dbbox-db-key-v1`, info `db_id`)) → OPFS-Container `z8blobs.vfs`
  (SyncAccessHandle, Index-Header, 64 KiB). Kein zweiter DB-VFS.
- **Blob-Weg:** `OpfsBackend` implementiert
  `z8run_core::dbnode_contract_storage::StorageBackend` (read/write/list/
  delete/kind) über denselben SyncAccessHandle-Container — optionale
  lokale Blob-Cache-Schicht, klar getrennt vom DB-VFS.

## wasmi-Nachrichtenprotokoll (identisch nativ)

App-WASM exportiert:
- `z8_alloc(len: i32) -> ptr`
- `z8_dealloc(ptr, len)`
- `z8_process(ptr, len) -> ptr`: an `ptr` steht `u32 LE` Länge, danach
  JSON-Antwort.

Der Host reicht `AppRequest` (JSON) rein und bekommt `AppReply` (JSON)
raus. Sandbox: leere `Linker`-Importliste — jeder Import (`fs`, `net`,
WASI) scheitert bei der Instanziierung. Echo-App (`apps/echo/echo.wasm`)
ist dieselbe Datei wie nativ (Signatur = SHA-256 über die Eingabe-Bytes).

**Wichtig:** wasmi läuft im Browser mit dem `portable-dispatch`-Backend.
Das Tail-Call-Backend rekurriert pro Instruktion und sprengt auf
`wasm32` den JS-Stack; `portable-dispatch` ist Pflicht.

## Login-Flow (Passbox → S3 → Master)

1. `POST /v1/login/passbox` mit `space`, `username`, `password`,
   `hw_pem`, `salt`, `s3{host,region,access_key,secret_key,bucket,prefix}`
   und optional `hash_key` (Default `Argon2IDHashDatei.txt`).
2. Hashdatei wird per SigV4-**GET von S3** geholt (Format
   `Argon2IDHashDatei/2`). Sie wird NIE in OPFS/IndexedDB geschrieben.
3. `Argon2id(name,salt)` → User-Adresse (Base32[0..32], klein).
4. Passbox öffnen: Schlüssel = `Argon2id(password,salt)` (m=19456,
   t=2, p=1), AES-256-GCM mit AAD `kv-login-passbox` → Provider-Shard.
5. Hardware-Box: ECIES-P256 (ECDH, HKDF `kv-m2-secretbox`, AES-GCM, AAD
   `kv-hwbox`) → HW-Shard. v2/v3 (ML-KEM) wird klar abgelehnt.
6. Shamir 2-of-2 über GF(2^8) → Master (nur RAM, zeroize).
7. Session + Token aus `proxy-kern`; DB `demo` (oder erster
   Passbox-Bucket) wird geöffnet. Fehlt S3 → **fail-closed Shutdown**;
   danach antworten DB-Endpunkte mit `503 fail-closed` (kein Schreiben mehr).
   Falsches Passwort → `401 Passwort falsch`, kein Token.

**Es gibt keinen `master_b64`-Direkteingang** (`grep -rn master_b64
crates/z8run-browser/src` = leer). Die Test-Welt ist hinter dem Feature
`test-login`; der echte Bündelbau aktiviert es nicht.

## CORS-Regeln (Endstand)

DD-CORS (`/etc/z8run/s3.json`, Bucket `dd-1441-zerr-remote-main`):

| Methode | Origins | Foreign-Origin |
|---|---|---|
| GET/HEAD/PUT/POST/DELETE | `https://riss.zerr-remote.de`, `https://riss.144.76.188.158.sslip.io`, `http://127.0.0.1:*`, `http://localhost:*` | 403 |

Die frühere **bucketweite GET-Wildcard ist entfernt**. S3-CORS kann
technisch NICHT auf ein Prefix (`kronvault/b2b/...`) eingeschränkt
werden — Regeln gelten pro Bucket. Ein separater b2b-Bucket wäre der
saubere Weg, die vorhandenen Zugangsschlüssel dürfen aber keine Buckets
anlegen (`CreateBucket` = AccessDenied). Deshalb: strikte Origin-Liste
für alles. **Abweichung vom Plan:** „b2b-GET von überall" ist nicht
mehr möglich; Login funktioniert nur von den gelisteten App-Origins.

## Tests

- Native: `cargo test --workspace` (3× sequenziell).
- Browser (headless Chrome, dedicated worker):
  `cargo test -p z8run-browser --target wasm32-unknown-unknown
   --features test-login --test wasm`
- E2E gegen dev-S3: Login → Token → DB-Query, falsches Passwort,
  OPFS ohne Hashdatei (Rohlog in `verify-logs/z8-proxy3b/`).
- Export: `z8-export --target browser` erzeugt `wasm/`, `worker.js`,
  `index.html`; `--target native` unverändert.
