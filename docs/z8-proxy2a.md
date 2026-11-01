# z8-proxy2a — Zwei-Logging-Welten, PQC-TLS, Ein Port

Build auf PROXY-1 (`e4102b2`). Der Proxy bleibt ein nativer Dienst neben
z8run; neu sind die Logging-Naht, die Meta-Welt, der fail-closed WAL-Stopp,
die PQC-TLS-Schicht und der Ein-Port-Front in z8run.

## Zwei Welten, nie vermischt (FEST 21)

| Welt | DB | Inhalt | Lebensdauer |
|---|---|---|---|
| OTel (KI) | `otel` (je User-Cluster) | Spans: Prompt/Antwort-Kontext, Modell, `trace_id`, `engine_id`, Dauer, Status, Richtung | User-Eigentum, JSONL-Export |
| Meta (Ereignis) | `meta` (global) + `meta-cluster` (Cluster) | `{actor, action, objekt_ref, trace_id, session, status, detail, ts_ms}` — `detail` ist Kurz-Kontext, NIE Inhalt | WORM, unloeschbar |

Beide DBs werden beim Login mit demselben Master geoeffnet (nicht im
Session-Scope sichtbar). `KV_PROXY_OTEL_DB`, `KV_PROXY_META_DB`,
`KV_PROXY_CLUSTER_META_DB` konfigurieren die IDs.

### Span-Schema (OTLP/W3C-kompatibel, eigen gebaut)

```json
{"trace_id":"32hex","span_id":"16hex","parent_span_id":"16hex?",
 "name":"llm.call","attrs":{},"start_ms":0,"end_ms":0,
 "status":"ok|error","engine_id":"...","direction":"in|out|internal"}
```

`traceparent` (`00-<trace>-<span>-<flags>`) wird gelesen und geschrieben.
Der Proxy garantiert den Rueckfall: fehlt/ist der Kontext kaputt, erzeugt
und injiziert er selbst. Jeder HTTP-Aufruf kann `traceparent` mitschicken;
`llm.call`, `app.call` und `db.write` landen im selben Trace.

### Ereignis-Decke (12 Arten)

`login, logout, flow_start, flow_end, app_call, call_happened, export,
blob_upload, delete, reservation_change, cluster_open, cluster_close`.
Jede Aktion erzeugt mindestens eine Meta-Zeile. WORM ist auf DB-Ebene
durch `BEFORE DELETE/UPDATE`-Trigger erzwungen (nicht nur Konvention).

## Subscribe/Push-Naht

`EventHub` (`crates/proxy/src/subscribe.rs`): der Proxy PUSHT aktiv an
registrierte Senken (`Filter` je Cluster/Quelle/Art), fire-and-forget.
Pull ist das Sicherheitsnetz: `since(cursor)` liefert alle Ereignisse mit
`seq > cursor` (Wiederaufnahme nach Absturz, nichts doppelt/verloren).
Logging (Meta + OTel) publiziert ueber genau diese Naht.

## WAL-Stress = Shut-up (fail-closed)

`WalGuard`: WAL-Fehler, Timeout oder Rueckstand > `KV_PROXY_WAL_PENDING_LIMIT`
=> geordneter Verkehrsstopp. Ab dann antwortet jeder HTTP-Aufruf mit
**503 `UNAVAILABLE`**, DB-Schreibvorgaenge werden abgelehnt, der
Serve-Loop endet (Proxy DOWN). Es gibt keinen Bypass.

## Secret-Injektion

Secrets liegen im `SecretStore` (zeroize). Platzhalter `{{secret:ns/name}}`
werden AUSSCHLIESSLICH am LLM-/API-Ausgang ersetzt; Klartext wird nach dem
Senden geschreddert. Logs/Spans/Antworten enthalten nur Referenz + sha256
(tresor-proxy-Regel). Apps sehen nie Keys oder Prompts.

## PQC-TLS (F18/F23)

- rustls `0.23.45` mit **aws-lc-rs** (Pflicht; ring kann kein ML-KEM).
- `X25519MLKEM768` wird hart priorisiert, klassische Gruppen (X25519,
  SECP256R1/384R1) bleiben Fallback.
- Beim Handshake wird die verhandelte Gruppe geloggt (`TLS-Handshake
  verhandelt … gruppe=… pqc=true|false`) — Score-Daten fuer die Botwall.
- Beweisclient `z8-tls-proof` (gleiche rustls+aws-lc-rs): `--legacy`
  bietet nur klassische Gruppen an (Fallback-Beweis).
- TLS 1.3/1.2, ALPN `http/1.1`, Certificate/Key ueber `Z8_TLS_CERT` /
  `Z8_TLS_KEY`. Liegt der MLKEM nicht im Angebot, verweigert der Start.
- ACME: `rustls-acme 0.15` ist als Abhaengigkeit fuer die Phase-2-
  Uebernahme deklariert; der Cutover in diesem Build nutzt das vorhandene
  gueltige LE-Zertifikat (kein Doppel-ACME waehrend Caddy noch lief).

## Ein Port (F20)

z8run bindet 443 direkt (nur wenn `Z8_HTTPS_PORT` gesetzt ist) und routet:

| Pfad | Ziel |
|---|---|
| `/proxy/*` | kv-proxy (intern 127.0.0.1:7800) |
| `/login/v1/*`, `/kvlogin/*` | kv-login (intern 127.0.0.1:7710) |
| alles andere (inkl. exakt `/login`) | z8run-Engine/UI |

`/login` exakt bleibt die z8run-SPA — sonst waere die UI tot (Abweichung
von der pauschalen `/login/*`-Regel, bewusst zugunsten der Funktion).

## Endpunkte (neu)

| Methode | Pfad | Zweck |
|---|---|---|
| GET  | `/v1/spans?trace_id=` | Spans eines Traces |
| POST | `/v1/meta/query` | `{trace_id?,action?,limit}` |
| GET  | `/v1/trace/full?trace_id=` | Spans + Metas in EINER Antwort (Beweis) |
| POST | `/v1/export/otel` | `{trace_id?}` -> JSONL + MANIFEST (sha256 + HMAC-Siegel) |

MCP `z8_proxy` kennt zusaetzlich `span_query`, `meta_query`, `export_otel`,
`trace_full`.

## Konfiguration

`KV_PROXY_OTEL_DB`, `KV_PROXY_META_DB`, `KV_PROXY_CLUSTER_META_DB`,
`KV_PROXY_WAL_PENDING_LIMIT`, `KV_PROXY_EXPORT_DIR`, `KV_PROXY_EXPORT_KEY`
(hex 32 Byte / Base64). TLS: `Z8_HTTPS_PORT`, `Z8_HTTPS_BIND`,
`Z8_TLS_CERT`, `Z8_TLS_KEY`, `Z8_PROXY_ADDR`, `Z8_LOGIN_ADDR`.

## Nicht in 2a

WebSocket/Telefonie/Fan-out voll, Gesamt-Export-Archiv, `udsv3://`,
Browser/OPFS, Matrix-SDK, S3-Relay, Debug-Plugin-UI, ACME-Cutover.
