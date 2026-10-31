# VERIFY-BERICHT Z8-PROXY2B — NEONGRÜN (nach 2 Audit-Runden)

Stand: 01.11.2026, Branch `z8-proxy2b`, HEAD `e6ae326` (gepusht auf `fork`).
Repo: `/data/z8run-test/src`. Bauplan: `bauplan-z8-proxy2b.md` (v1).
Rohlogs: `/data/z8run-test/verify-logs/z8-proxy2b/`.

## Ergebnis je Stufe

| Stufe | Ergebnis | Beweis |
|---|---|---|
| S0 Sicherung/Platz | GRÜN | `s0-sicherung.log`, `s0-baseline-1..3.log` (501×3), 16 GB frei vor S4 |
| S1 Kanal-Kern | GRÜN | `s1_channel.log`: 7 Tests (Claim-Streit, Grace/Reconnect, Fan-out, Overflow+echtes Meta, HOL, Frame LE+flags, Limits) |
| S2 Endpoint/Duplex/Relay | GRÜN | `s2_stream.log`: 5 Tests (Auth, Rotation im Socket, Duplex, 200 Frames payload+typ+flags identisch, BAD_FRAME/CLAIM_DENIED) |
| S3 Aufnahme/Migration | GRÜN | `s3_migration.log`: echte Blob-Session, SHA-gleich, 12-Chunk-Wiedergabe, Recording-HTTP start/stop/playback, alte Endpunkte 404 |
| S4 Last-Folter ×20 | GRÜN | `s4-folter-x20-final.log` (20×60 s, kombiniert) |
| S5 Gesamt-Export | GRÜN | `s5_export.log` (Voll/Selektion/Filter/Freeze/Kette/PQC/Secret-Hülle/HTTP-E2E) |
| S6 Nodes/MCP/Doku/Install | GRÜN | `s6-install-proof.log`, Demo-Flow, docs/z8-proxy2b.md (im Git) |

## S4-Zahlen (alle Grenzen eingehalten)

`FOLTER_ENDE dauer_s=1200 rounds=20 p99_us_max=16930 hol_us_max=13277
lost=0 fanout_min=1000 rss_pro_lauf_max_kb=2124 rss_cum_max_kb=5384
ws=2000 rot=20000 phone_frames=80000 events_dropped=995417
ws_p99_us_max=1286 rss_load_max_kb=11780 alive_tasks_max=438`

- p99 Relay-Latenz **am `/v1/stream`-Endpunkt**: 1.286 ms < 5 ms.
- Kein Head-of-Line: schneller Abonnent bekam alle Frames; Publisher-Dauer
  unter CPU-Sättigung 13.3 ms (Info, nicht Kriterium).
- 0 verlorene Aufnahme-Chunks; 0 Verbindungsablehnungen (2000/2000).
- Telefonie: 80.000/80.000 Frames zugestellt (40 Gespräche × 2 Richtungen).
- RSS über Startwert während Last 11.5 MB < 15 MB; Task-Sampler max 438 < 5000.
- Live-Event-Overflow 24.9 % (erlaubt: Live schlägt Vollständigkeit;
  Aufnahme verliert nichts). Kriterium für „0 Verlust“ sind Aufnahme-Kanäle.

## S5-Export-Beweise

- Voll-Export: spans/meta/linefs/flows/apps/blobs + Binär-Blob, SHA je Datei,
  Hash-Kette im Manifest und beim Öffnen nachgerechnet (Manipulation = Fehler).
- Selektion `worlds=["otel"]` → nur `spans.jsonl`; Session-/Zeitraumfilter
  (auch LineFS `ts` RFC3339) positiv und negativ getestet.
- Freeze: DB-Reservierung blockiert sowohl Export (Reservierungsfehler) als
  auch jeden Schreiber; Aktion nach Export fehlt im alten Container.
- PQC-Pyramide: Passwort-Container öffnet, falsches Passwort = Fehler;
  Empfänger-PQC-Key (`recipient_pub_b64` + `recipient_kem_ek_b64`) im
  Container-Kern getestet (richtiger Key öffnet, falscher nicht).
- Secrets nur als Name + versiegelte Hülle (Container-Key), nie Klartext.

## S6

- `kv-stream` (open/subscribe/claim/release/push) + `kv-export` registriert;
  Demo-Flow `Z8-STREAM` im Canvas (7 Nodes, x=0..1440, sauberes Layout).
- MCP `z8_proxy`: `stream_open`, `stream_subscribe`, `stream_claim`,
  `stream_push`, `export_all` (+ bestehende Aktionen).
- Installation: `z8run` mit `--features embed-ui`, `kv-proxy`, Dienste aktiv;
  UI HTTPS 200; PQC `X25519MLKEM768` true, Legacy X25519 false.
- Doku `docs/z8-proxy2b.md` im Git; alter MCP-Pfad `/v1/stream/blob/meta` = 404,
  neue Endpunkte = 401 ohne Token.

## Tests

`cargo test` 3× sequenziell (100 s Pause): **515 passed / 0 failed** je Lauf
(`s6-cargo-test-1..3.log`). Baseline 501×3 (`s0-baseline-*`). ≥501 erfüllt.

## Audit-Historie

- Audit 1: 5 GRÜN / 7 GELB — behoben (Overflow-Meta zentral, Header-Pflicht,
  Altcode weg, Folter ehrlich, Export-Freeze/Filter/Hüllen, Doku im Git).
- Audit 2: restliche GELB — behoben (kombinierte Last, WS-p99, Telefonie-
  Zustellung, Recording/Playback-HTTP, Kettenprüfung, PQC-Empfängerkey,
  Limits, Session-Identität/Claim-Pflicht, Modulaufteilung).

## Bewusste Abgrenzungen (dokumentiert, keine stille Ausnahme)

- Registry-interner p99/HOL steigt unter CPU-Sättigung (200k Events); das
  Kriterium ist die Endpunkt-Latenz (1.286 ms). Beide Werte stehen im Log.
- Demo-Flow ist ein Layout-/Integrationsbaustein; die Funktion wird durch
  `s2_stream`/`s3_migration`/`s5_export` (echte Endpunkte) bewiesen.
- Testdateien dürfen >200 Zeilen sein (Prüf-Harness, kein Produktcode);
  Produktmodule wurden auf ≤205 Zeilen geteilt (`export_all` 77,
  `export_worlds` 158, `export_collect` 173, `channel` 205).
- SIP/RTP/Telefonnummern bleiben externe App (G9), nicht Teil dieses Builds.
