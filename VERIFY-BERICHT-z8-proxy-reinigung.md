# VERIFY-BERICHT Z8-PROXY-REINIGUNG

Bauplan: `bauplan-z8-proxy-reinigung.md` (v2-Audit, 02.11.2026).
Branch: `z8-proxy-reinigung`.
Logs: `/data/z8run-test/verify-logs/z8-proxy-reinigung/` (Rohlogs, nicht im Repo).

## S0 — Sicherung + Quellen-Jagd + Beweis-Frischung

| Punkt | Ergebnis | Beweis |
|---|---|---|
| Branch + Ausgangscommit | `z8-proxy-reinigung` ab `96bc951` | `s0-baseline.log` |
| Plattenplatz | 19G frei (93% belegt) | `s0-baseline.log` |
| Backup Runtime-DB | `backups/z8-proxy-reinigung/data-1793652343.tgz` + `z8run.db.1793652343` | `s0-baseline.log` |
| Test-Baseline (eingefroren) | **534 passed / 0 failed** (`cargo test --workspace`) | `s0-baseline-test.log` |
| WASM live | HTTP 200, 3.310.895 Bytes | `s0-register.log`, `s0-beweise.log` |
| Bundle /data/z8run/wasm | 6.644.070 Bytes (= 6,64 MB dezimal; `du` 6.4 MiB) | `s0-register.log` |
| z8run_browser.wasm vor wasm-bindgen | 2.236.028 Bytes | `s1-dual-compile.log` (proxy3b) |
| wasmtime-Adapter | 106 Zeilen, `wasmtime::Module`, `WasmSandbox`, `KvApp` | `s0-register.log` |
| echo.wasm SHA-256 | `69779494875e7a57b8ea2e36b5f26430906e86ee340371b0154273f01fb5801e` | `s0-register.log` |
| Setup-UI/API auf 443 | `/setup-ui/` = 404, `POST /setup-ui/v1/init` = 404 | `s0-register.log`, `s0-beweise.log` |
| Login nativ + Browser | `s4-login-e2e.log` vorhanden | `s0-register.log` |
| OpenRouter-Key | gültig, beide Zielmodelle PRESENT | `s0-openrouter.log` |

Hinweis `6,6 MB`: 6.644.070 Bytes dezimal = 6,64 MB; `du -sh` zeigt 6.4 MiB.
Beide Zahlen beziehen sich auf denselben Bundle-Stand (inkl. `wasm.bak`).

Status S0: **GRUEN**.

## S1 — Quellen-Konsolidierung

Rohliste: `/data/ghosthand/ROHLISTE-z8-proxy-reinigung.md` (Kopie
`docs/ROHLISTE.md` im neuen Repo). Jede Regel mit Quelle + Beweis-Pfad:
FEST 1–34, G1–G10 (wörtlich), devstack §16–21, Proxy-Baupläne 1/2a/2b/3/3b,
alle fünf VERIFY-Berichte, die fünf Teil-Dokus, WAL/Quorum/LineFS-Konzepte.
Session-Jagd: 445 Sessions, 40 eindeutige User-Texte der Proxy-/KronVault-
Sessions (`verify-logs/z8-proxy-reinigung/s1-session-usertexte.txt`) — keine
Regel außerhalb der Dokumente gefunden. Status: **GRUEN**.

## S2 — Neues reines Repo

Ort: `/data/z8run-proxy` (eigenes Git-Repo, Commit `2b09118`).
Enthält nur: `proxy-kern`, `proxy` (Runtime), `bins/kv-proxy`, `apps/echo`,
`deploy/`, `docs/`. Kein Canvas/API/CLI/UI/Browser-Ballast
(`docs/ABHAENGIGKEITEN.md`, `s2-cargo-tree.log`).

| Punkt | Ergebnis | Beweis |
|---|---|---|
| Pfad-Pin | `z8run-core` + `z8run-runtime` @ `96bc951`, Login/Setup NICHT kopiert | `Cargo.toml`, `docs/ABHAENGIGKEITEN.md` |
| Cargo-Tree begründet | jede direkte Crate + zwei Pfad-Crates begründet | `s2-cargo-tree.log` |
| Dual-Compile | nativ + `proxy-kern` wasm32 grün, echo.wasm gebaut | `s2-dual-compile.log` |
| Tests | 50 passed / 0 failed im neuen Repo = **exakt** Proxy-Scope der alten Baseline (50/0) | `s2-test-1.log`, `s2-test-original-proxyscope.log` |
| Verhalten identisch | neues `kv-proxy`-Binary: Login (udsv3) → Token → DB-Write/Query über laufenden z8run-DB-Node → Fremd-DB 403 → Logout 401 | `s2-e2e-newrepo.log` |

Hinweis Baseline: S0 friert 534/0 für den **gesamten** Alt-Workspace ein.
Das neue Repo enthält nur die Proxy-Pakete; deren Anteil ist 50/0 und
in beiden Repos byte-gleich (kein Test verloren, keine Neuerfindung).
Status: **GRUEN**.
