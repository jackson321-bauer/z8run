# z8-proxy3 — PORT-KILL, UDSV3, RAM-HARDENING, BROWSER-KERN, EXPORTER

Build auf `z8-proxy2b` (edb64e3 + Docs). Dieser Bericht beschreibt den
Stand nach S1–S5. Abweichungen vom Bauplan stehen ausdrücklich unter
„Bewusste Abgrenzungen“ — keine stille Ausnahme.

## Port-Map NACH dem Kill

| Port | vorher | nachher |
|---|---|---|
| 443 | PQC-TLS-Front (z8run) | **bleibt** PQC-TLS-Front, routet UDS |
| 7700 | z8run Engine HTTP | **entschieden** (Engine nur `/data/z8run/z8run.sock`) |
| 7710 | kv-login HTTP | **entschieden** (`/data/z8run/kv-login.sock`) |
| 7800 | kv-proxy HTTP | **entschieden** (`/data/z8run/kv-proxy-admin.sock`) |

`ss -tlnp` zeigt nach dem Deployment nur noch 443 (plus systemfremde
Dienste). Desktop-Modus (ohne `serve`) darf für den lokalen Browser
zusätzlich Loopback-TCP öffnen; `serve`/Produktion nie.

## UDSV3 (FEST 10/18)

Frame: `[u32 len][u64 counter][12 nonce][u32 ct_len][ciphertext]`, alle
Zahlen BE. Nonce ist ZUFÄLLIG je Frame (gleicher Klartext erzeugt nie
zweimal dieselben Bytes); Replay derselben Bytes wird zusätzlich über
ein transkriptweites 300-s-Fenster abgewiesen (Hash aus Kontext+Frame),
damit ein Mitschnitt auf einer NEUEN Verbindung nicht wieder greift.
Schlüssel = `HKDF-SHA256(Transport-Master, Salt "z8-udsv3",
Info "udsv3|<socket-kontext>")`, AES-256-GCM, Nonce = 4 Nullbytes +
Counter, AAD = Kontext + Counter. Jede Richtung hat einen eigenen
Counter; ein Frame mit erwartetem Counter wird genau einmal akzeptiert
(Replay = Fehler). Der Transport-Master liegt NUR in
`/data/z8run/udsv3.key` (0600, z8run) oder `Z8_UDSV3_MASTER`; er steht
nie im Repo.

Kontexte: `login` (veralteter Handoff), `admin` (Proxy-Admin-UDS),
`dbnode-msg` (Proxy → z8run DB-Node), `kv-login` (443-Front → kv-login),
`engine` (z8run.sock).
Klartext ist im Default VERBOTEN. Nur `Z8_UDSV3=off` erlaubt Klartext
und schreibt ein Meta-Ereignis `udsv3_downgrade` (JSONL, `meta=true`).

Beweise: `s1-udsv3-live.log` (Login→Proxy→DB, Frame-Hex = Chiffre),
`cargo test -p z8run-core --test udsv3_e2e` (Chiffre/Replay/Downgrade).

## RAM-Hardening (FEST 12)

`Z8_RAM_LEVEL` 0..3 (Default 2):

- 0 = aus, 1 = zeroize, 2 = mlock-Arena + mlock je Master/Hülle,
- 3 = zusätzlich `MADV_DONTDUMP`, `PR_SET_DUMPABLE=0`, RLIMIT_MEMLOCK hoch.

`SessionState` nullt den Master bei Drop und versucht mlock;
`KeyEnvelope` ebenso. systemd-Units setzen `LimitMEMLOCK=infinity`.
Beweis: `/proc/<pid>/status` `VmLck: 68 kB` (z8run) / `72 kB`
(kv-proxy) plus `ram::tests::mlock_erzeugt_vmlck_und_drop_nullt`.

## SQLite / File-Cipher (FEST 25, Weg A)

SQLCipher ist KOMPLETT entfernt (auch nativ). SQLite läuft plain; die
Verschlüsselung liegt in `dbnode/file_cipher.rs` (Z8FC1): AES-256-GCM
part-weise (1 MiB), Part-Key = HKDF(DB-Key, `z8-file-cipher-v1`, Part),
AAD = Magic + Part. `dbnode/cipher_vfs.rs` ist ein SQLite-VFS (inkl.
WAL/xShm), der ausschließlich Z8FC1-Dateien liest/schreibt. Snapshots
sind dieselbe Chiffre. Ein falscher Master öffnet nichts; Alt-Welten
werden nur mit `Z8_DB_MIGRATE_OLD=1` EINMAL umbenannt (Log), danach ist
das Flag wieder aus.

Beweise: `dbnode_cipher_file` (grep = Chiffre), `s3-live-cipher-files.log`
(live `5a38464331` = `Z8FC1`), `dbnode_wasm_compat` (WASM-Datei nativ
lesbar).

## Browser-Kern (Worker, WASM)

`crates/z8run-browser` kompiliert für `wasm32-unknown-unknown`:

- SQLite als C (`sqlite-wasm-rs`, eigene sqlite3.c, thin bindings),
  sqlite-vec EINGEBRANNT über `sqlite3_auto_extension` (kein dlopen).
  Beweis: `WASM_VEC_VERSION=v0.1.9` (`s3-wasm-vec-node.log`) und
  Chrome-Test `s3-wasm-selftest.log`.
- OPFS über `SyncAccessHandle` im Worker (Main-Thread-Test nutzt den
  async Writable-Fallback). Datei = Z8FC1-Chiffre, dieselbe Form wie
  nativ.
- EIN Worker für DB+Fassade; die UI spricht `postMessage` mit
  HTTP-Semantik (`facade(json)`), Status/DB/Session/S3-Probe.
- S3: SigV4 pure Rust (AWS-Testvektor exakt) + `fetch`-Glue.
- AutoLock: Default 300 s, `0` = aus, nur UI-Session; Inaktivität
  nullt Session+Master. Offline: S3-Probe false ⇒ SHUTDOWN, Writes
  verboten. Konflikt: älterer OPFS-Stand + neuere S3-WALs ⇒ Replay
  ab `local+1` + UI-Meldung; gleicher Stand + andere Kette ⇒
  `ChainMismatch`.
- COOP/COEP werden NICHT gesetzt (kein Multi-Worker/SAB nötig).
- `persist()` und `Quota` werden über `navigator.storage.persist()` /
  `estimate()` abgefragt; der Selftest liefert `persisted`/`quota` im
  JSON. iOS-Safari-Quirk: `SyncAccessHandle` ist in Safari < 17 nicht
  verfügbar und der `persist()`-Grant ist dort nicht garantiert —
  der Worker nutzt in diesem Fall den async `createWritable()`-Fallback
  (kein Multi-Worker, keine harten Garantien); Quota muss nach dem
  ersten Schreibvorgang erneut gelesen werden.

## Exporter-Allziel

`z8-export` (EIN Werkzeug):

- `--target native`: Linux baut + läuft (Beweis `s5-native-export.log`,
  `s5-native-run.log`); Windows/macOS als `build_bar`-Spalten über
  `rustc --target ... --emit=metadata` (kein Linker/Testgerät nötig).
- `--target browser`: baut `crates/z8run-browser` (wasm-bindgen web)
  und legt `worker.js` + `index.html` + `wasm/` ab. Ausgeliefert über
  den 443-Front unter `/wasm/*` (`Z8_WASM_DIR`), kein file://-Test.
  Beweis: `s5-browser-443.log` (`FASSADE={"status":200,...}`).
- Mobile-Triples sind nur Dokumentations-Spalten, nicht gebaut.

## CORS (DD-Bucket)

Regeln (Reihenfolge ist wichtig; DO matcht die erste passende Regel):

1. eigene Origins (`riss.zerr-remote.de`, sslip.io): GET/PUT/HEAD/POST/DELETE,
2. `*`: nur GET/HEAD (b2b-Hashdateien für Login überall).

Preflight-Beweise: `s5-cors-set.log` (GET von fremder Origin = 200,
PUT von fremder Origin = 403, PUT eigene Origin = 200).

## WAMR-Ausweichpfad

Apps laufen im Browser NICHT (wasmi fehlt, s. Abgrenzung 2). Falls später
Multi-Worker/SAB nötig wird, ist WAMR (wasm-micro-runtime) der im Plan
genannte Ausweichpfad; COOP/COEP würden dann NUR dafür gesetzt. Aktuell
gibt es keinen Multi-Worker und keine SAB-Abhängigkeit.

## Mobile-Spalten (nur vorbereitet, NICHT gebaut)

`aarch64-linux-android`, `aarch64-apple-ios`, `aarch64-apple-ios-sim`
stehen als Ziel-Spalten im Exporter-Konzept; es gibt keine Mobile-
Binaries, keine Telefonie-App, kein APNs/P2P in diesem Build.

## CORS-Blocker (DD-One-Bucket)

S3-CORS kann NICHT nach Prefix unterscheiden. Der Bucket enthält
b2b-Hashdateien UND session/WAL-Objekte; die Regel `*` für GET/HEAD
gilt daher technisch für den ganzen Bucket (auch session/WAL-GET von
fremden Origins). Das ist die im Plan genannte DD-CORS-Falle: kein
stilles Umgehen, sondern dokumentierter Blocker. Saubere Lösung wäre
ein eigener Bucket/Host für b2b-Hashdateien (Hausmeister-Weg) — nicht
in diesem Build umgesetzt. PUT/POST/DELETE sind weiterhin auf die
eigenen Origins beschränkt.

## Bewusste Abgrenzungen (G6, keine stille Ausnahme)

1. **OPFS ist Persistenzschicht, kein SQLite-VFS.** SQLite läuft im
   Worker-RAM; nach Sync wird die DB als Z8FC1 über SyncAccessHandle
   nach OPFS geschrieben. Der Plan nannte „OPFS-VFS“; die gewählte
   Variante nutzt dieselben SyncAccessHandle, dieselbe Chiffre und
   dieselbe Replay-/Konfliktlogik, aber SQLite sieht kein OPFS.
2. **dbnode/proxy-Kern ist nicht 1:1 im WASM.** Im Browser liegen
   SQLite+vec, File-Cipher, OPFS, S3/SigV4, Session/AutoLock/Offline
   und die Fassade. Der native `DbNode` (async Storage/WAL-Dateien)
   bleibt nativ; Apps via wasmi und der komplette Login-Passbox-Flow
   im Browser sind NICHT gebaut (Folgeplan, FEST 23a/24).
3. **S3 im Browser**: Signierung + fetch sind implementiert und der
   AWS-Vektor ist bewiesen; ein echter Browser-Login gegen die
   dev-Welt braucht CORS + Zugangsdaten und ist hier nicht als
   UI-E2E gelaufen.
4. **Alte dev-Welten** wurden einmal umbenannt (`*.alt-<ts>`) und
   werden beim nächsten Login/Setup neu als Z8FC1 angelegt.
