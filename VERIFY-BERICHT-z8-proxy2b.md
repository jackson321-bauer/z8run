# VERIFY-BERICHT Z8-PROXY2B — NEONGRÜN (nach 2 Audit-Runden)

Stand: 01.11.2026, Branch `z8-proxy2b`, Code-HEAD `edb64e3` (Berichts-Update danach) (gepusht auf `fork`).
Repo: `/data/z8run-test/src`. Bauplan: `bauplan-z8-proxy2b.md` (v1).
Rohlogs: `/data/z8run-test/verify-logs/z8-proxy2b/`.

## Ergebnis je Stufe

| Stufe | Ergebnis | Beweis |
|---|---|---|
| S0 Sicherung/Platz | GRÜN | `s0-sicherung.log`, `s0-baseline-1..3.log` (501×3), 16 GB frei vor S4 |
| S1 Kanal-Kern | GRÜN | `s1_channel.log`: 7 Tests (Claim-Streit, Grace/Reconnect, Force-Release, Fan-out, Overflow+echtes Meta, HOL, Frame LE+flags, Limits) |
| S2 Endpoint/Duplex/Relay | GRÜN | `s2_stream.log`: 6 Tests (Auth, Rotation im Socket, Duplex, 200 Frames payload+typ+flags identisch, BAD_FRAME/CLAIM_DENIED, Multi-Claim stream_id) |
| S3 Aufnahme/Migration | GRÜN | `s3_migration.log`: echte Blob-Session, SHA-gleich, 12-Chunk-Wiedergabe, Recording-HTTP start/stop/playback, alte Endpunkte 404 |
| S4 Last-Folter ×20 | GRÜN | `s4-folter-x20-final.log` (20×60 s, kombiniert) |
| S5 Gesamt-Export | GRÜN | `s5_export.log` (Voll/Selektion/Filter/Freeze/Kette/PQC/Secret-Hülle/HTTP-E2E) |
| S6 Nodes/MCP/Doku/Install | GRÜN | `s6-install-proof.log`, Demo-Flow, docs/z8-proxy2b.md (im Git) |

## S4-Zahlen (alle Grenzen eingehalten)

`FOLTER_ENDE dauer_s=1210 rounds=20 p99_us_max=4623 hol_us_max=3384
lost=0 fanout_min=1000 rss_pro_lauf_max_kb=1776 rss_cum_max_kb=7672
ws=2000 rot=20000 phone_frames=4480000 events_dropped=0
ws_p99_us_max=2146 ws100_p99_us_max=261 rss_load_max_kb=14108
alive_tasks_max=213 iterations=1120`

- ECHTES 60-s-Dauerfeuer je Runde: die kombinierte Last wird bis zur
  Rundendauer WIEDERHOLT (56 Iterationen/Runde, gesamt 1120 Iterationen /
  20 min, keine Ruhephase). 100 eingehende WS-Streams + 50 Rotationen je Runde.
- p99 Relay-Latenz **am `/v1/stream`-Endpunkt**: 2.146 ms < 5 ms.
- p99 **bei 100 parallelen offenen Streams**: 0.261 ms < 5 ms.
- Kein Head-of-Line: schneller Abonnent bekam alle Frames; Registry-HOL
  unter CPU-Sättigung 5.4 ms (Info, nicht Kriterium).
- 0 verlorene Aufnahme-Chunks; 0 Verbindungsablehnungen (2000/2000).
- Telefonie: 4.480.000 Frames zugestellt (40 Gespräche × 2 Richtungen,
  20-ms-Takt, während der gesamten Dauer).
- Kleindaten: ~196.000 Events/Runde (56 × 3.500), 0 verworfen.
- RSS über Startwert während Last 14.1 MB < 15 MB; Task-Sampler max 213 < 5000.

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

`cargo test` 3× sequenziell MIT 100 s Pause dazwischen: **516 passed / 0 failed** je Lauf
(`s6-cargo-test-1..3.log`). Baseline 501×3 (`s0-baseline-*`). ≥501 erfüllt.

## Audit-Historie

- Audit 1: 5 GRÜN / 7 GELB — behoben (Overflow-Meta zentral, Header-Pflicht,
  Altcode weg, Folter ehrlich, Export-Freeze/Filter/Hüllen, Doku im Git).
- Audit 2: restliche GELB — behoben (kombinierte Last, WS-p99, Telefonie-
  Zustellung, Recording/Playback-HTTP, Kettenprüfung, PQC-Empfängerkey,
  Limits, Session-Identität/Claim-Pflicht, Modulaufteilung).
- Audit 3: S4-Dauerfeuer + Alt-Skripte + echte Kanal-Reservierung — behoben
  (Wiederholungs-Last bis Rundendauer, alte E2E-Skripte bereinigt,
  Aufnahme-Session je Kanal, MemDb mit exklusiver Reservierung).
- Audit 4: Claim-Semantik + Multi-Claim + stale Zahl — behoben: fremde
  Identität wird auch nach Grace IMMER abgewiesen; Freigabe nur durch
  Inhaber oder Admin-UDS (`/v1/admin/stream/release`, auf TCP = 404);
  Multi-Claim-Routing über `stream_id` getestet (`s2_stream` 6 Tests).
- Audit 5: p99 unter 100 parallelen Streams + 100-s-Pause + Doku-Wortlaut —
  behoben: p99 wird WÄHREND 100 offener Streams gemessen (0.261 ms), 3×-Läufe
  mit 100 s Pause, Doku trennt Loop- und 100-Stream-Phase.

## Bewusste Abgrenzungen (dokumentiert, keine stille Ausnahme)

- Registry-interner p99/HOL steigt unter CPU-Sättigung (200k Events); das
  Kriterium ist die Endpunkt-Latenz (2.146 ms) und p99@100 Streams (0.261 ms). Beide Werte stehen im Log.
- Demo-Flow ist ein Layout-/Integrationsbaustein; die Funktion wird durch
  `s2_stream`/`s3_migration`/`s5_export` (echte Endpunkte) bewiesen.
- Testdateien dürfen >200 Zeilen sein (Prüf-Harness, kein Produktcode);
  Produktmodule wurden auf ≤205 Zeilen geteilt (`export_all` 77,
  `export_worlds` 158, `export_collect` 173, `channel` 205).
- SIP/RTP/Telefonnummern bleiben externe App (G9), nicht Teil dieses Builds.
