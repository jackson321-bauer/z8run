# VERIFY-BERICHT — Z8-KVWEITERENTWICKLUNG

Bauplan: `bauplan-z8-kvweiterentwicklung.md` (v2, 129 Zeilen)
Datum: 2026-11-02
Ort Produktion: `/data/kronvault/kv-store`
Ort Dev-Klon: `/data/kronvault/kv-store-dev` (waehrend Entwicklung)
Git: Repo `/data/kronvault`, Branch `z8-kvweiterentwicklung`
HEAD bei Bericht: `dfaa1144` (S1 `9515ee46`, S2 `1adb72df`, S3 `81f5f2b9`,
S4 `6ad6dc9a`, S4-Nachtrag `48587fb3`, S4-Nachtrag2 `dfaa1144`)
Rohlogs: `/data/z8run-test/verify-logs/z8-kvweiterentwicklung/`

## GESAMTURTEIL: GRUEN

Alle Planstufen S0–S4 und die Abnahmekriterien sind mit Rohlogs am
Endpunkt belegt. Der unabhaengige Zero-Kontext-Audit (Runde 1 und 2)
hatte nur GELB-Punkte (Prozess/Doku); alle sind behoben und in Runde 3
bestaetigt. Kein funktionaler Punkt ist ROT.

Wichtige Planzahl-Abweichung (Doku, kein Fehler): Der Bauplan nennt
„z8run-Workspace 533" bzw. „530". Real sind es **534 passed / 0 failed**
— identisch in Baseline und nach der Aenderung. Die Planzahlen sind
veraltet; die entscheidende Bedingung „unveraendert gruen" ist erfuellt.

## S0 — SICHERUNG + SNAPSHOT: GRUEN
Log: `s0-sicherung.log`, `s0-kv-store-baseline.log`,
`s0-z8run-baseline.log`.
- Branch `z8-kvweiterentwicklung` angelegt, Baseline-Arbeitsstand
  gesichert (`a9f45004`).
- Dev-Klon `/data/kronvault/kv-store-dev`; MD5 aller `src/`+`examples/`
  identisch (`IDENTISCH` im Log).
- Baseline kv-store: 1 passed / 0 failed.
- Baseline z8run-Workspace: 534 passed / 0 failed.
- `/data` frei: 25 GB (≥ 15 GB).

## S1 — S3-ADAPTER: GRUEN
Log: `s1-live-beweis.log`, `s1-unit.log`.
3 Provider × 3 Mechanismen, jeweils am Endpunkt:
| Provider | MPU/HEAD unsichtbar | ListParts Resume | Complete SHA | Range@Partgrenze | put_if_absent |
|---|---|---|---|---|---|
| Linode | None (unsichtbar) | 2 Parts | `b8b36a56…` | byte 17, Part2 `832bd3fb…` | 1.=Angelegt, 2.=412 |
| Impossible-Cloud | None | 2 Parts | `4a253671…` | byte 158, Part2 `e1766931…` | 1.=Angelegt, 2.=412 |
| DigitalOcean | None | 2 Parts | `6abbedb2…` | byte 42, Part2 `914567c3…` | 1.=Angelegt, 2.=412 |
- `put_if_absent`: Inhalt nach dem 2. Versuch unangetastet (`erster`).
- Unit-Tests: 4/4 (nach Split: 9/9, siehe S4).

## S2 — QUORUM-WRAPPER: GRUEN
Logs: `s2-crash-resume.log`, `s2-claim.log`, `s2-fallback.log`,
`s2-caps.log`, `s2-verify100.log`, `s2-postrefactor*.log`.
- Crash/Resume 3 Runden: exit 137 (kill -9), gleiche `upload_id`
  `01M6E6ZBA3KR62J27MB5ZBW4F6`, completed `[1,2] → [1,2,3,4] →
  [1,2,3,4,5,6,7]`, finale Runde `abgeschlossen:true`; danach
  100-MB-Objekt auf allen 3 Providern byte-gleich
  (`a208e641c38100b8…`).
- Doppel-Claim: erster `true`, zweiter gleiche Epoch `false` (Exists);
  Epoch-Fencing: `epoch2` uebernimmt, altes `epoch1`-ACK danach `false`;
  Doppel `epoch3` → genau einer `true`. Claim nutzt KEIN unbedingtes
  Overwrite mehr: je Epoch ein Key via `put_if_absent`, hoechste Epoch
  gewinnt, Verlierer wird geloescht; ACK mit Nachkontrolle.
- Fallback: erzwungen `range=false` → `weg:"EinzelPut"`,
  104857600 Bytes, E2E unveraendert.
- Capability-Probe: 3× `mpu=true range=true if_none_match=true`.
- 100-MB-Testblob E2E byte-gleich auf allen 3 Providern.
- Finaler Claim-Lauf nach der ACK-Nachkontrolle (`s2-claim-final.log`,
  HEAD-Stand): alle acht Bedingungen wie oben, GRUEN.

## S3 — INTEGRATION + BEWEIS GROSS: GRUEN
Logs: `s3-put1g.log`, `s3-zeitvergleich.log`, `s3-resume1g.log`,
`s3-verify1g.log`, `s3-z8run-workspace.log`.
- 1-GB-Objekt (Müll-Daten, Seed 99), SHA
  `25c88c015a0d64573b4178255c86541ac4a670cbbc5c9b65672df5c5c2873d30`.
- Zeitvergleich (16×64 MiB): parallel (max 4 im Flug) 34'010 ms,
  sequenziell 60'033 ms → **1,765×** schneller.
- kill -9 mitten im Transfer (exit 137), Checkpoint `upload_id
  2~cgfjbZ8dU5ZWnxI0BcvZX3eSMf4CtK_`, completed `[1]`; Neustart
  uebertrug die restlichen 872'415'232 Bytes und schloss ab
  (`abgeschlossen:true`). ListParts fand dabei bereits hochgeladene,
  noch nicht gecheckpointete Parts (echte Resume-Heilung).
- 1-GB-Verify: 3 Provider byte-gleich (gleicher SHA).
- z8run-Workspace unveraendert: 534 passed / 0 failed (Baseline 534).
  Zusaetzlich auf dem FINALEN HEAD erneut voll gelaufen:
  `s4-z8run-workspace-final.log` = 534 passed / 0 failed / 14 ignored.
  (Ein erster Lauf traf die flaky Timing-Zeile
  `s6_secret_export_trace` mit 11,0 ms > 10 ms unter Systemlast; der
  Einzeltest lief isoliert in 0,24 s GRUEN, der volle Lauf danach
  534/0. Kein kv-store-Bezug.)
- Cleanup: Prefix `kvweiterentwicklung/` in allen 3 Buckets
  0 Objekte / 0 offene MPUs (boto3 LIST, nur lesend).

## S4 — SCHARF SCHALTEN + DOCS: GRUEN
Logs: `s4-build-release.log`, `s4-smoke.log`,
`s4-final-test-clippy.log`.
- Release-Binary neu gebaut (`cargo build --release`, 27–30 s).
- Smoke-Roundtrip ueber das Release-Binary:
  Input-SHA `1e974ef7…`, Output-SHA `1e974ef7…`, `CMP=IDENTISCH`,
  `replicas_ok` = 3, `replicas_failed` = [] , Delete „gelöscht in 3
  Buckets".
- `.bak`-Sicherung vor dem Scharfschalten:
  `src/s3.rs.bak-z8-kvweiterentwicklung-20261102`,
  `src/lib.rs.bak-z8-kvweiterentwicklung-20261102`,
  `kv-target/release/kv-store.bak-z8-kvweiterentwicklung-20261102`,
  `kv-target/debug/kv-store.bak-z8-kvweiterentwicklung-20261102`.
  (Die `.bak`-Dateien sind per `.gitignore *.bak-z8-*` nicht getrackt.)
- README: neue Methoden, Capability-Fallback (nur Range-Quelle bzw.
  MPU-Ziel; `if_none_match` nur Claim), WAL-Ausnahme, EXPLIZITE
  TEIL-STEUERUNG, Krypto-Abgrenzung, .bak-Pfade.
- Finaler Test/Clippy-Lauf auf dem ausgelieferten Split-Code:
  9/9 Tests, clippy ohne Warnung.

## BESTANDS-SCHUTZ: GRUEN
`git diff a9f45004..HEAD -- kv-store/`: bestehende Methoden
`put_object/get_object/list_objects/delete_object` und
`quorum::write/read/list/delete/info` unveraendert; `quorum.rs`,
`main.rs`, `provider/*` nicht angefasst. Neu nur additive Module/Methoden.
Konsumenten (dbnode, hausmeister, ketten-arzt, devstack, z8-setup)
nicht geaendert; dbnode/z8run-Tests 534/534.

## WAL / KRYPTO / SECRETS: GRUEN
- WAL: kein MPU/`upload_part`/`MpuHandle` im WAL-Pfad (0 Treffer);
  WAL bleibt atomarer Einzel-PUT.
- Krypto: 0 Treffer fuer aes/gcm/chacha/poly1305/encrypt/decrypt im
  kv-store-eigenen Code (nur transitive `Cargo.lock`-Eintraege).
- Secrets: 0 Treffer in `git log -p a9f45004..HEAD -- kv-store/`,
  Worktree und Logs; echte Provider-Keys nur in
  `/data/kronvault/.m5-dev/s3-multi-providers.json` (nicht getrackt),
  nie in Kontext/Logs ausgegeben.

## DATEIGROESSEN (AGENTS-Regel)
Alle NEUEN Dateien ≤ 191 Zeilen:
`quorum_transfer.rs 191`, `s3_mpu.rs 169`, `s3_range.rs 115`,
`claim.rs 115`, `s3_request.rs 93`, `checkpoint.rs 81`,
`capability.rs 77`, `s3_common.rs 58`, `s3_parts.rs 56`,
`quorum_helpers.rs 53`, Shims `s3_ext.rs`/`quorum_ext.rs` 7.
`s3.rs` ist durch Auslagern von Baseline 380 auf 340 Zeilen GESCHRUMPFT.
Die bereits vor dem Bauplan uebergrossen Dateien `quorum.rs` (227),
`main.rs` (224) und `provider/gcp.rs` (244) bleiben unveraendert und
sind nicht Teil dieses Bauplans.

## ZERO-KONTEXT-AUDIT
- Runde 1 (nach S3): GELB — S4 uncommitted, neue Dateien > 205,
  README-Fallback zu breit, Planzahlen 533/530 vs. real 534,
  Claim-TOCTOU. Alle Punkte adressiert.
- Runde 2 (nach S4): GELB — README-Wortlaut, fehlender Test/Clippy-Log,
  Smoke ohne Hash, VERIFY-Bericht fehlte. Adressiert durch
  `s4-final-test-clippy.log`, `s4-smoke.log` mit SHA + CMP, diesen
  Bericht, README-Praezisierung, ACK-Nachkontrolle.
- Runde 3 (nach diesen Korrekturen): **GRUEN** in allen 10 Pruefpunkten
  (Git/README, Dateigroessen, Test/Clippy final, Smoke mit SHA+CMP,
  Claim ohne Overwrite + ACK-Nachkontrolle, funktionale Kette,
  Bestandsschutz, WAL/Krypto/Secrets/Cleanup, .bak+Release, VERIFY an
  beiden Orten). Die drei nicht-blockierenden Resthinweise wurden
  danach ebenfalls geschlossen: README-Nit `checkpoint` (nicht
  re-exportiert) korrigiert; voller Workspace-Lauf auf finalem HEAD
  `s4-z8run-workspace-final.log` = 534/0; Live-Claim nach der finalen
  ACK-Zeile `s2-claim-final.log` GRUEN.

## REPRODUKTION (Kurz)
```
export PATH=/root/.cargo/bin:$PATH
cd /data/kronvault/kv-store && cargo test && cargo clippy --all-targets
KV_STORE_CONFIG=/tmp/kv-targets.json cargo run --example s3_transport_proof
# S1: 3 Provider x 3 Mechanismen
KV_STORE_CONFIG=/tmp/kv-targets.json cargo run --example kohorte_proof -- \
  transfer KEY 0 1 64 CK "" 4
KV_STORE_CONFIG=/tmp/kv-targets.json cargo run --example kohorte_proof -- \
  claim PREFIX
```
(`/tmp/kv-targets.json` enthaelt die 3 Provider-Targets; Secrets
niemals committen oder ausgeben.)
