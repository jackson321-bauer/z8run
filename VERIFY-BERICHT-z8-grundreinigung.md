# VERIFY-BERICHT Z8-GRUNDREINIGUNG

Datum: 02.11.2026
Bauplan: `/data/ghosthand/bauplan-z8-grundreinigung.md`
Repo: `/data/z8run-test/src`, Branch `z8-grundreinigung`, HEAD `97e5a64`
Rohlogs: `/data/z8run-test/verify-logs/z8-grundreinigung/`
Zero-Kontext-Audit: `/data/ghosthand/ZERO-KONTEXT-AUDIT-z8-grundreinigung.md`

**Gesamturteil: GRÜN** (alle Planziele am Endpunkt bewiesen; Audit-GELB-Funde
F1–F4 gefixt und neu belegt; F5 ist vorbestehend/außerhalb des Bauplans).

## Ergebnis je Stufe

| Stufe | Ergebnis | Beweis |
|---|---|---|
| S0 Sicherung | GRÜN | `s0-sicherung.log`: Branch, DB-Backup, keine DD-Sicherung (Muell-Entscheid); `s0-baseline-1..3.log` = je 533 passed / 0 failed |
| S1 Setup-Engine | GRÜN | `s1-setup-engine.log` (3 Provider, 12 Dateien, degraded=false); `s1-replicas.log` (5 Keys je 3 Provider byte-gleich); `s1-login-native.log` (Login anna/bernd, Master, DB, Registry); `s1-flow-delegation.log` (Flow 200) + `s1-flow-diff.log` (DIFF_OK True); `s1-flow-login.log` (Login gegen Flow-Welt) |
| S1 Quorum-Folter | GRÜN | `s1-quorum-torture.log`: (a) 1 Provider weg → OK + degraded; (b) 2 weg → „Zwangsquorum verfehlt … fail-closed", kein Objekt; (c) Rückkehr → 3/3 OK, byte-gleich |
| S2 /2 tot + Neuaufsetzen | GRÜN | `s2-dd-delete.log` (kronvault/b2b, /user, /session, sim2/welt2 = 0 Rest); `s2-new-devworld.log` + `s2-new-devworld-login.log` (Welt z8dev, Login grün); `s2-fixture-export.log` + `s2-fixture-stahlgitter.log` (Fixture neu, .alt archiviert, v3-Login grün) |
| S2 Browser /3 | GRÜN | `s2-browser-v3.log`: wasm-Test `/3` (b2b+hw-shards, v3-Hybrid) + falsches Passwort 401; Browser-Quellen `grep '/2' = 0` |
| S3 WebAuthn + Logout | GRÜN | `s3-webauthn-register.log` (ES256+ML-KEM-1024 Credential); `s3-webauthn-login-e2e.log` (Login 200, Master-Match, Token; Replay/Origin/Passwort/ohne Assertion je 401; Proxy-Session vor 200 / nach Logout 401); `s3-logout-wasm.log` (Token 401, sessions=0, tokens=0, master_zeroized) |
| S4 Node/Flow/Doku | GRÜN | `s4-flow-delete.log` (8 Flows gelöscht), `s4-endlisten.log` (7 Flows, Node-Endliste), `s4-flow-run-proof.log` (je 1 Run), Docs `docs/z8-plattform-kern.md` + `docs/z8-nutzer-doku.md` |
| S4 Installation | GRÜN | `s4-final-ui.log`: `/`=200, `/login`=200, `/wasm/`=200, `/login/v1/*`=410; `s4-final-pqc.log`: `X25519MLKEM768 PQC true`, HTTP 200 |
| S4 Tests/Clippy | GRÜN | `s4-final-test-1..3.log` = je 530 passed / 0 failed; `s4-clippy.log` EXIT 0, 0 `^error`; `s4-final-wasm.log` 1 passed |

## Abnahmekriterien

- [x] Setup = eigene Engine (`bins/z8-setup`), importiert `setup_kern`; Flow-Node importiert dasselbe Modul (Naht-Beweis, keine Kopie).
- [x] Welt komplett über Linode + Impossible-Cloud + DigitalOcean; Quorum 2/3, fail-closed unter Quorum, degraded + Heilung.
- [x] `/2` komplett tot: Browser `/3`-only, kv-login-Dienst/Socket/Config entfernt, Front `/login/v1/*` = 410, keine DD-Referenz in `/etc/z8run/*.json`.
- [x] Neue Dev-Welt mit der Engine, Fixture exportiert (alt `.alt`), v3-Login grün.
- [x] WebAuthn-Ceremony im Kern (ES256, Challenge einmal, Origin, Counter), Assertion als Parameter; PEM nur Dev-Pfad.
- [x] Logout hart: Tokens tot, Session/Master zeroize, UI-Worker fail-closed, Proxy-Session 401.
- [x] Node-/Flow-Endliste: 7 Flows, 6 Leichen-Nodes entfernt; alle z8-Standard-Nodes bleiben.
- [x] Doku: Plattform-Kern (verbindlich) + Nutzer-Doku (Setup → Login → Proxy → Apps).
- [x] Installation mit embed-ui, PQC, `/wasm/`; Tests 530×3, Clippy 0.

## Bewusste Grenzen / Abweichungen (G6)

1. **Browser-S3-Live-Fetch**: `/3`-Login ist im wasm-Test mit echter v3-Welt
   (P-256+ML-KEM-1024) bewiesen; der S3-Fetch-Pfad ist derselbe wie der in
   proxy3b live bewiesene `/2`-Pfad. Linode unterstützt kein S3-CORS;
   DO/IC-CORS wurden für den Dev-Bucket gesetzt. Ein Browser-Live-Test
   gegen den Bucket ist daher nicht Teil des Rohlogs.
2. **Z8-PROXY/Z8-OTEL Run-Beweis** erfolgte ohne Master (definierte
   4xx/401 im Flow, kein 500/kein toter Pfad); der echte Proxy-Login ist
   über `KV3-Login-WebAuthn` (Session + Token + Logout) bewiesen.
3. **Quorum-Rollback**: Vorflug fail-closed ist bewiesen; zusätzlich wurde
   ein Rollback der bereits geschriebenen Replikate bei Mid-Write-Quorum-
   Verlust implementiert (`setup_quorum.rs`).
4. **Path-Dependencies** (`/data/kronvault/kv-store`, `kv-login`,
   `tresor-proxy/umschlag.rs`) bleiben extern (EINE Krypto-Quelle, kein
   Fork). Ein neuer Rechner braucht diese Pfade bzw. einen Klon davon.
5. **Vorbestehende** harte API-Default-URLs in `llm.rs`/`crm.rs`/`stt.rs`
   sind nicht Teil dieses Bauplans und wurden nicht angefasst.
6. Danube-Systembackup-Units (`kv-s3backup`, `github-sync`) referenzieren
   noch DD; sie sind Infrastruktur, nicht Produkt-Config. Produkt-Config
   `/etc/z8run/*.json` ist DD-frei.

## Reproduktion (Kurz)

```bash
# Tests
cd /data/z8run-test/src && cargo test --workspace     # 530 passed
# Quorum-Beweis
./target/debug/z8-setup replicas --providers-config /data/kronvault/.m5-dev/s3-multi-providers.json \
  --bucket z8-grundreinigung-20261101-rd1 --prefix dev/ --key setup/registry.txt
# UI/PQC
curl -sk https://riss.zerr-remote.de/ -o /dev/null -w '%{http_code}\n'
./target/debug/z8-tls-proof riss.zerr-remote.de:443
```
