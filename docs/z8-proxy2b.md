# z8-proxy2b — Stream-Protokoll, Folter, Gesamt-Export

Build auf PROXY-2A (`8216d78`). Ein generischer WebSocket-Endpoint
`/v1/stream` mit Kanal-Modell (Claim, Fan-out, 16-Byte-Frames), Aufnahme
parallel zum Live-Strom, Last-Folter ×20 und selektiver Gesamt-Export
ueber die PQC-Pyramide. Die alte SSE/chunked-Geradeausleitung aus PROXY-1
ist ENTFERNT (noch nie produktiv).

Die bestehende Engine-Canvas-WS `/engine` (Log-Ereignisse des Editors)
bleibt unveraendert und hat mit Kanaelen nichts zu tun.

## Ein Endpoint, vier Session-Typen

`GET /v1/stream` als WebSocket, Upgrade nur mit gueltigem Session-Token
(`Authorization: Bearer …` oder Subprotocol `z8.jwt, <token>`). Typ im
Header `X-Z8-Stream-Type`:

| Typ | Bedeutung | Kanal-Header |
|---|---|---|
| `live` | ein Schreiber (Claim) | `X-Z8-Channel` |
| `subscribe` | nur lesen | `X-Z8-Channel` |
| `duplex` | Telefon: 2 Kanaele A→B / B→A | `X-Z8-Channel`, `X-Z8-Peer-Channel` |
| `relay` | Live-API-Relay (OpenAI-Realtime/Gemini-Live-artig) | wie `duplex` |

Identitaet = die AUTHENTIFIZIERTE Session (Client-Header/Control-Feld
`identity` werden ignoriert — sonst waere Claim-Diebstahl per String
moeglich). Token-Rotation lebt im Socket weiter: Control-Frame `{"type":"token","token":"<neu>"}` prueft das
neue Token derselben Session, die Verbindung bleibt.

### Control-Frames (Text/JSON)

`subscribe {channel}`, `claim {channel, identity?}`, `release {channel}`,
`heartbeat`, `token {token}`, Antworten `ack` / `err {code, error}`.

### Medien-Frames (Binaer)

Header EXAKT 16 Byte, ALLE Zahlen **little endian**:

```
magic u16 (0x5A38) | typ u8 | flags u8 | stream_id u32 | seq u64
```

Danach Rohbytes. Die Laenge ergibt sich aus der WS-Framelaenge — KEIN
`len`-Feld. Der Proxy liest NUR Header + Routing, NIE den Inhalt: JSON,
Opus-20-ms, beliebige App-Protokolle laufen byte-genau durch. `seq` und
`stream_id` vergibt der Kanal beim Publish; `flags` wird durchgereicht.

## Kanaele, Claim, Fan-out

Adressierung `{app_id}/{kanal}` (dauerhaft) oder
`{app_id}/{kanal}/{session_id}` (fluechtig). Limits (Env, Defaults):
Abonnenten/Kanal 32, Kanaele/Session 64, Frame max 1 MiB.

- **Ein Schreiber je Kanal.** Der Claim gehoert einer IDENTITAET, nicht dem
  Socket. Reconnect derselben Identitaet erbt den Claim (Grace ist nur
  Reconnect-Buchhaltung); eine fremde Identitaet erhaelt IMMER
  `CLAIM_DENIED` — auch nach dem Grace-Fenster. Freigabe nur explizit per `release` (Inhaber)
  oder `POST /v1/admin/stream/release` (hoehere Instanz, nur 0600-Admin-UDS);
  niemals automatischer Diebstahl.
- **Fan-out mit eigenem Ringpuffer je Abonnent.** Publish sperrt nur kurz,
  macht kein `await`: ein langsamer Abonnent kann andere NIE blockieren
  (kein Head-of-Line). Puffer voll = aelteste Frames verwerfen +
  Meta-Ereignis `stream_overflow` (Live schlaegt Vollstaendigkeit;
  Aufzeichnung kommt aus Blobs und verliert nichts).
- **Telefonie:** Gespraech = 2 Kanaele, je eigener Claim; Frames bleiben
  native 20-ms-Opus. Gruppen: 1 Sprecher-Kanal + Fan-out, Sprecherwechsel
  ist Claim-Uebergabe.
- **Aufnahme:** Die App meldet einen Kanal zur Aufnahme an; derselbe Kanal
  laeuft parallel als verschluesselte Blob-Session (ein Mitschnitt, kein
  zweiter Stream). Wiedergabe = normale Kanal-Wiedergabe.

## Steuer-API fuer Nodes/MCP

`POST /v1/stream/ctl` (Token) mit
`{action: open|subscribe|claim|release|push, channel, identity?, payload_b64?, typ?, limit?}`.
`subscribe` liefert bis zu `limit` bereits gepufferte Frames als
`frames_b64` (kurzer Poll). `push` ist NUR mit Claim derselben Session
erlaubt (`Push ohne Claim` = Fehler). Der Medienpfad bleibt der WebSocket.

## Gesamt-Export (G12–G15)

`POST /v1/export/all` (Token), Body:

```json
{"worlds": ["linefs","blobs","otel","meta","flows","apps"],
 "db_id": "demo", "sessions": [], "from_ms": null, "to_ms": null,
 "password": "<Empfaenger-Passwort>"}
```

Leere `worlds` = alle. Der Export RESERVIERT die beteiligten DBs (blockiert
jeden Schreiber), liest DANN den WAL-Stand N und sammelt JSONL (`spans`, `meta`, `linefs`, `flows`, `apps`,
`blobs`-Metas) + Binaer-Blobs (`blobs/<sid>.bin`), bildet je Datei sha256
und eine Hash-Kette und legt alles in einen PQC-Container
(`z8-export-container/1`). Empfaenger oeffnen ueber die Pyramide mit
Passwort (oder PQC-Pubkey); falscher Schluessel = Fehler, jede Datei wird
gegen das Manifest geprueft. Secrets stehen NUR als Name + versiegelte
Huelle (mit dem Container-Key verschluesselt) im Manifest, nie im Klartext.

Antwort: `{"manifest": {...}, "container_b64": "..."}`.

## Last-Folter (G10/G11)

`cargo test --release folter --features folter`, Szenarien a–f, ×20
(Dauer per `Z8_FOLTER_SECS`, Standard 60 s; Gesamt 20 min). Gemessen am
Endpunkt (Release, 60-s-Runden):

Die Kanal-/Telefonie-/Event-/Relay-Last laeuft je Runde GLEICHZEITIG und
wird bis zur Rundendauer WIEDERHOLT (60 s Dauerfeuer, keine Ruhephase;
56 Last-Iterationen/Runde, gesamt 1120 Iterationen / 20 min). Je Runde
laufen zusaetzlich 100 eingehende WS-Streams und 50 Rotationen; die
p99-Messung erfolgt WAEHREND die 100 Streams offen sind.

| Grenze | Ergebnis |
|---|---|
| p99 Relay-Latenz am `/v1/stream`-Endpunkt < 5 ms | **2.146 ms** |
| p99 bei 100 parallelen Streams < 5 ms | **0.261 ms** |
| Head-of-Line | **kein HOL**: schneller Abonnent bekam alle Frames (per-Sub-Ring) |
| Verlorene Aufnahme-Chunks | **0** |
| Telefonie-Zustellung (40 Gespraeche × 2 Richtungen, 20-ms-Takt) | **4.480.000** Frames |
| Kleindaten-Events pro Runde | ~196.000 (56 × 3.500), 0 verworfen |
| Connection-Ablehnung | **0** (2000/2000 WS) |
| Proxy-RSS ueber Startwert < 15 MB | **14.1 MB** waehrend Last (7.7 MB am Rundenende) |
| Token-Rotationen | **20.000** |
| Task-Stau | keine (Sampler waehrend Last, max 271 Tasks) |

Szenarien: 20 VNC-Streams, 40 Telefon-Sims, 200.000 Kleindaten-Events,
100 Abonnenten Fan-out, 50 parallele Rotationen, 100 eingehende Streams.
Die Kanaele sind ueber die Runden FEST (Steady-State-Messung). Der
Test-Prozess enthaelt die Clients; `malloc_trim` gibt nur freigegebene
Arenen an das OS zurueck, der LIVE-Heap wird weiter gemessen. Der
Registry-interne p99/HOL-Wert liegt unter CPU-Saettigung durch die
Events hoeher und ist nur Info — das Kriterium ist der Endpunkt.
Rohlog: `/data/z8run-test/verify-logs/z8-proxy2b/s4-folter-x20-final.log`.

## Custom Nodes / MCP / Demo

- `kv-stream` (open/subscribe/claim/release/push) und `kv-export`
  (export_all) als duenne Canvas-Nodes ueber den Admin-UDS.
- MCP `z8_proxy`: `stream_open`, `stream_subscribe`, `stream_claim`,
  `stream_push`, `export_all` (+ bestehende Aktionen).
- Demo-Flow `Z8-STREAM`:
  `crates/z8run-core/tests/fixtures/z8-proxy2b-stream.flow.json`,
  Installation `scripts/z8_proxy2b_demo_flow.py`.

## Externe Gateways (G9) — nur Platz im Bild

SIP/RTP/Telefonnummern sind eine EXTERNE App ausserhalb des Proxys (wie
der Browser). Sie spricht als normaler API-Client das Stream-Protokoll.
Nicht Teil dieses Builds; keine Provider-spezifische Logik im Proxy.

## Konfiguration

`KV_PROXY_STREAM_SUBS` (32), `KV_PROXY_STREAM_QUEUE` (256),
`KV_PROXY_STREAM_GRACE_MS` (5000). Export nutzt den bestehenden
DB-/Storage-Pfad; keine echten URLs/Keys im Produktcode (Gateway-Regel).
