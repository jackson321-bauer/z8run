# z8-proxy1 — Proxy-Kern (PROXY-1)

Der Proxy ist die Engine-Schicht zwischen Login, DB-Node, WASM-Apps und
LLM. In PROXY-1 läuft er nativ als kleiner API-Server neben z8run; derselbe
Kern wird in PROXY-2 als Browser-Bibliothek verwendet.

## Aufbau

```
crates/proxy-kern/   target-sauberer Kern (keine fs/net/socket-APIs)
  traits.rs          Clock, Random, StoragePort, DbPort, LlmPort, ByteSource/Sink
  token.rs           kurzlebige, rotierende Session-Tokens (Grace)
  state.rs           SessionState/SessionStore, Master nur RAM (zeroize)
  prompts.rs         PromptStore (RAM + Zeroize, nie serialisiert)
  stream.rs          Ringpuffer + pump (konstanter RAM, Reihenfolge)
  app.rs             KvApp v0: init/handle/cleanup, JSON rein/raus + Stream
crates/proxy/        Nativ-Adapter
  adapters/native    SystemClock, OsRandom, FsStorage
  adapters/db        UdsDbClient -> DbNodeCommand/Event über UDS
  adapters/login     Listener auf kv3-proxy.sock (roher JSON-Line + HTTP)
  adapters/wasm      WasmKvApp auf der vorhandenen z8run-runtime-Sandbox
  bundle.rs          manifest.json + app.wasm + prompts.enc (DB-Siegel)
  service.rs         ProxyConfig/ProxyService, NoDb, MockLlm
  db_api.rs          token+scope-geschützte DB-Operationen
  app_api.rs         App-Liste/Call, LLM-Call mit Prompt-Injektion
  stream_api.rs      12-Chunk-Blob (chunked) + SSE
  http*.rs           Router: öffentlich (TCP) und admin (0600-UDS)
apps/echo/           Echo-Beweisapp (wasm32-wasip1, no_std, keine Imports)
bins/kv-proxy/       Dienst-Binary + `seal-prompts`
```

### Nahtstellen

- **Login-Handoff:** Proxy lauscht auf `/data/z8run/kv3-proxy.sock`. Der
  bestehende WebAuthn-Login (`unix-out`, `bodyPath=proxy_session`) sendet
  `addr_space`, `addr_user`, `master_key_b64`, `workspace_bucket`, `engines`.
  Der rohe `kv3-socket`-Line-Modus wird ebenfalls akzeptiert. Der Master wird
  nie geloggt und nur im RAM gehalten (Zeroize beim Drop).
- **DB-Kanal:** z8run startet `z8run_core::dbnode::msg_uds` auf
  `/data/z8run/dbnode-msg.sock` (0600). Protokoll: eine JSON-Zeile
  `DbNodeCommand` rein, eine JSON-Zeile `Vec<DbNodeEvent>` raus. Der Proxy
  öffnet **keine** DB-Datei und bettet keine eigene Engine ein.
- **Apps:** `KvApp` mit `init/handle/cleanup`; die WASM-Implementierung ruft
  `z8_process` auf der z8run-runtime-Sandbox auf. Die Sandbox hat **keine
  Host-Imports** — fs/net/clock sind ohne Capability nicht erreichbar
  (Import => Instanziierung scheitert).
- **Prompts:** `prompts.enc` = Zeilen `name<TAB>base64(text)`, versiegelt mit
  dem DB-Siegel (HKDF-SHA256 + AES-256-GCM + HMAC-SHA256, AAD
  `bundle_id|1|`). Geöffnet beim Boot mit `KV_PROXY_BUNDLE_KEY`; Inhalt nur
  im RAM. Der LLM-Port bekommt den Prompt, Apps nie.

### Trait-Signaturen (Auszug)

```rust
pub trait Clock { fn now_ms(&self) -> u64; }
pub trait Random { fn fill(&self, buf: &mut [u8]); }

#[async_trait] pub trait StoragePort {
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, ProxyError>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>, ProxyError>;
}

#[async_trait] pub trait DbPort {
    async fn open_db(&self, db_id: &str, master_key_b64: &str, cluster: Value)
        -> Result<Value, ProxyError>;
    async fn query(&self, db_id: &str, sql: &str, params: Vec<Value>, readonly: bool)
        -> Result<Value, ProxyError>;
    // close/reserve/release/write/status/schema analog
}

#[async_trait] pub trait LlmPort {
    async fn complete(&self, system: &str, user: &str) -> Result<Value, ProxyError>;
}

pub trait KvApp: Send + Sync {
    fn name(&self) -> &str;
    fn info(&self) -> AppInfo;
    fn init(&self) -> Result<(), ProxyError>;
    fn handle(&self, input: &Value) -> Result<AppReply, ProxyError>;
    fn cleanup(&self) -> Result<(), ProxyError>;
}

pub trait ByteSource { fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProxyError>; }
pub trait ByteSink { fn write_chunk(&mut self, data: &[u8]) -> Result<(), ProxyError>;
                      fn finish(&mut self) -> Result<(), ProxyError>; }
```

## Endpunkte (öffentlich, localhost/UDS)

| Methode | Pfad | Zweck |
|---|---|---|
| GET  | `/v1/status` | Sessions/Tokens/Apps/Prompts (ohne Geheimnisse) |
| GET  | `/v1/session` | Session-Info zum Bearer-Token |
| POST | `/v1/session/rotate` | neues Token, altes stirbt nach Grace |
| POST | `/v1/session/logout` | Session + alle Tokens töten |
| POST | `/v1/db/query` | `{db_id,sql,params,readonly}` (scope-geprüft) |
| POST | `/v1/db/write` | `{db_id,sql,params}` (Reserve/Release) |
| GET  | `/v1/db/status?db_id=` | DB-Status |
| GET  | `/v1/db/schema?db_id=` | DB-Schema |
| GET  | `/v1/db/scope` | erlaubte db_ids |
| GET  | `/v1/apps` | App-Infos |
| POST | `/v1/app/call` | `{app,input}` -> JSON + optionaler Stream |
| POST | `/v1/llm/call` | `{prompt,user}` -> Attrappe; Prompt nie in Antwort |
| GET  | `/v1/stream/blob` | 12-MiB-Blob, chunked, Ringpuffer |
| GET  | `/v1/stream/blob/meta` | `{chunks,chunk_size,total,sha256}` |
| GET  | `/v1/stream/events` | 12 SSE-Events in Reihenfolge |

**Admin-UDS** (nur `/data/z8run/kv-proxy-admin.sock`, 0600):
`POST /v1/admin/session` mit Login-Payload + `open_dbs`.

## Canvas-Node und MCP

- Node `kv-proxy` (Kategorie `data`): Aktionen `session_open`, `status`,
  `app_list`, `app_call`, `db_query`; spricht den Admin-UDS. Demo-Flow
  `Z8-PROXY`: Login-Handoff -> kv-proxy -> db-query -> Antwort.
- MCP `z8_proxy`: `status`, `session_open`, `session_close`, `app_list`,
  `app_call`, `stream_open` (Treiber: `/data/z8run/mcp/z8_proxy_run.py`).

## Deployment (nativ)

- `systemd kv-proxy.service`, `User=z8run`, `EnvironmentFile=/etc/z8run/proxy.env`
  (`KV_PROXY_*`, `Z8_DBNODE_SOCK`, `KV_PROXY_BUNDLE_KEY`).
- Bundle: `manifest.json` (`name,version,app,prompts`), `app.wasm`,
  `prompts.enc`; `kv-proxy seal-prompts --out ... --prompts ...` erzeugt das
  Siegel aus `KV_PROXY_BUNDLE_KEY`.
- Der dbnode-Ordner muss dem z8run-Benutzer gehören (Engine schreibt dort).

## Nicht in PROXY-1

PQC-TLS/`udsv3://`, Endpunkt-Registry, RAM-Hardening, Browser/OPFS, echte
LLM-Endpoints, GhostHand als App, Provider/Hausmeister, Vouchers.
