# VERIFY-BERICHT Z8-PROXY3B — Stand 01.11.2026

Repo: `/data/z8run-test/src`, Branch `z8-proxy3b` (Basis `0ff4626`).
Bauplan: `/data/ghosthand/bauplan-z8-proxy3b.md`.
Rohlogs: `/data/z8run-test/verify-logs/z8-proxy3b/`.

**Gesamturteil: GRÜN mit 3 benannten Abweichungen.** Alle fünf S4-Rot-
Punkte aus PROXY-3 sind funktional geschlossen: echter Kern im Worker,
wasmi-Apps, Passbox-Login über S3, OPFS am StorageBackend-Trait,
CORS-Wildcard entfernt. Die Abweichungen sind technisch begründet (G6).

## Ergebnis je Stufe

| Stufe | Ergebnis | Beweis |
|---|---|---|
| S0 Sicherung | GRÜN | `s0-sicherung.log`; Branch, DB-Backup, 54 GB frei, Target vorhanden |
| S0 Baseline | GRÜN | `s0-baseline-1.log` = 533 passed / 0 failed |
| S1 Feature-Split | GRÜN | `s1-dual-compile.log`: wasm32 `--no-default-features` + nativ grün; `s1-native-test.log` = 533/0; keine doppelten Dateinamen |
| S2 Kern im Worker + OPFS | GRÜN | `s2-wasm-test.log` (Chrome/dedicated Worker): `kern=proxy-kern`, `dbnode=wasm-vfs+z8fc1`, DB open/exec/query, DB-Datei Z8FC1, OpfsBackend-Trait roundtrip, native Z8FC1-Fixture in OPFS gelesen |
| S3 wasmi-Apps | GRÜN | `s3-wasm-test.log`, `final-wasmi-probe.log`: echo.wasm unverändert, SHA-256-Signatur korrekt, Import-App (`env.fs_read`) trappt bei Instanziierung, Prompt nie in App-Antwort |
| S4 Passbox-Login | GRÜN | `s4-login-e2e.log` (headless Chrome, echter SigV4-GET gegen dev-S3): Login 200 → Token → DB demo INSERT/SELECT; falsches Passwort 401; OPFS ohne Hashdatei; ohne S3 503+Shutdown (In-Crate) |
| S4 CORS | GRÜN mit Abweichung 1 | `s4-cors-set.log`, `s4-cors-preflight.log`: Wildcard entfernt, fremde Origin 403 für GET/PUT (auch b2b) |
| S5 Exporter/Install | GRÜN | `s5-install-export.log`: Binary HEAD+embed-ui installiert, 443 only, `/` `/wasm/` `/proxy/v1/status` `/login/v1/health` 200, PQC X25519MLKEM768; Browser-Bündel über 443 zeigt proxy-kern+dbnode; nativer Export gebaut+gelaufen (`{"a":"null","b":"left","c":"right"}`, rc 0) |
| S5 Doku | GRÜN | `docs/z8-proxy3b.md` |
| S5 Tests | GRÜN | `final3-test-1/2/3.log` = je **533 passed / 0 failed** (100 s Pause), `final-wasm-test.log` ok, `final-clippy.log` rc 0 |
| S5 Greps | GRÜN | `final-abnahme-greps.log`: `master_b64` in Browser-Quellen/Browser-Tests = 0; keine Test-Exporte im ausgelieferten Bündel; Dual-Compile grün |

## Harte Beweise (Auszug)

```
KERN_STATUS  {"kern":"proxy-kern","dbnode":"wasm-vfs+z8fc1","worker":true,...}
PASSBOX      status 200, token, db demo, space_addr/user_addr
DB           INSERT/SELECT browser-login-e2e; Datei beginnt mit Z8FC1, kein SQLite-Klartext
WRONG_PW     401 "Passwort falsch (Secretbox oeffnet nicht)", kein Token
OPFS         ["z8blobs.vfs"] (keine Hashdatei)
WASMI        echo signature == sha256(payload); Import-App trap
CORS         b2b GET app-origin 200; fremd-origin 403; PUT fremd 403
FASSADE      {"body":{"dbnode":"wasm-vfs+z8fc1","proxy_kern":"proxy-kern",...},"status":200}
cargo test   533 passed x3 (0 failed)
```

## Bewusste Abweichungen (G6)

1. **CORS kann nicht prefix-scopen.** S3-CORS-Regeln gelten pro Bucket;
   ein Prefix (`kronvault/b2b/...`) ist nicht adressierbar. Ein eigener
   b2b-Bucket wäre der saubere Weg, `CreateBucket` ist mit den vorhandenen
   Schlüsseln AccessDenied. Ergebnis: Wildcard komplett entfernt, feste
   Origin-Liste (App + Localhost-Dev). Damit ist „b2b-GET von überall"
   NICHT mehr möglich (Plan-Fall 1 ⇒ 403 statt 200) — sicherer, aber
   funktional enger. Login funktioniert von den gelisteten Origins.
2. **dbnode-Kern bleibt nativ-only.** sqlx/rusqlite/std::fs laufen nicht
   auf `wasm32-unknown-unknown`. Geteilt sind `dbnode_contract_types` und
   `dbnode_contract_storage` (EIN Code, keine Kopie); der Browser nutzt
   dieselbe Naht mit SQLite-im-WASM. Kein Fork, aber auch kein identischer
   WAL/Restore-Kern im Browser.
3. **Login-Hashdatei nur Schema `/2`; HW-Key als PEM.** Der Dev-B2B-Bestand
   nutzt `Argon2IDHashDatei/2` (JSON). Das `/3`-Textformat der
   Setup-Welt ist nicht implementiert. Der Hardware-Anteil kommt als PEM
   in den Login-Request (dev/FEST-15-Vorstufe); WebAuthn/Passkey-Bindung
   ist die nächste Großstufe (FEST 23a), nicht Teil von proxy3b.

Zusätzlich: Der erfolgreiche S3-E2E nutzte eine eigens erzeugte Test-Welt
im dev-Prefix `sim2/welt2/` (bekanntes Passwort/PEM), weil das Passwort
der live-b2b-Welt nicht vorliegt; der echte b2b-Fetch wurde ebenfalls
ausgeführt (S3 lieferte Hashdatei, Login wies das veraltete Fixture-
Passwort mit 401 ab). Die Test-Hashdatei wurde nach dem Lauf aus S3
gelöscht; keine Secrets im Repo.

## Testzahlen

- Baseline (`0ff4626`): **533 passed** ×1 (weitere Läufe im Log).
- Neuer Stand: **533 passed ×3**, 0 failed (100 s Pause).
- Browser: 1 In-Crate-Worker-Test + 2 wasmi-Probe-Tests grün.
- `cargo clippy --workspace --all-targets`: rc 0 (nur Bestandswarnungen).
