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
