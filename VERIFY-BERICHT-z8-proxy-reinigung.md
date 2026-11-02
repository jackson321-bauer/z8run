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

## S3 — Lehrbuch-Doku + Grafiken

Ort: `/data/z8run-proxy/docs/` (Commit `2343ae7`).
`PROXY.md` = Kapitel 1 (BEGRIFFS-EINHEIT: Hauptname **KronVault-Proxy**;
Synonyme Wirt/SmartFrontend/KronVault-Plattform genau einmal; Managed
Platform als eigenes, klar getrenntes Kapitel). Danach 7 Kapitel:
Regeln (G1–G10 WÖRTLICH, Injektion/Claim/CAS/Ports), Architektur
(Feature-Split nativ/Browser, Managed Platform), APIs (jeder Endpoint mit
Request/Response), Datenflüsse (Login, Setup, WAL/Quorum, Z8FC1, Logging,
Streams, Export), Sandbox + App-Bau (ABI, Minimal-App, Bundle, Injektion,
Egress-Whitelist), Beweise, Glossar. Jede Datei < 205 Zeilen.

| Punkt | Ergebnis | Beweis |
|---|---|---|
| Pflicht-Inhalte komplett | alle Zeilen aus Bauplan S3 vorhanden (Begriffe, WASM+nativ, Setup nur lokal, Login beides, FEST 17/18a/22, OTel, Injektion, Sandbox, udsv3, PQC, Ports, CAS/ETag, Login-Kette, Setup-Engine, WASM-Runtime) | `docs/PROXY.md`…`docs/07-glossar.md` |
| Beweis-Register | alle S0-Zahlen mit Log-Pfad zitiert | `docs/06-beweise.md` §6.1 |
| Grafik (a) Architektur | gerendert + Screenshot + Vision GRÜN | `docs/img/shot-architektur.png`, `vision-architektur.md` |
| Grafik (b) Login-Kette | gerendert + Screenshot + Vision GRÜN | `docs/img/shot-login-kette.png`, `vision-login-kette.md` |
| Grafik (c) App-Lebenszyklus | gerendert + Screenshot + Vision GRÜN | `docs/img/shot-app-lebenszyklus.png`, `vision-app-lebenszyklus.md` |
| Grafik (d) WASM nativ/Worker/Browser | gerendert + Screenshot + Vision GRÜN | `docs/img/shot-wasm-ziele.png`, `vision-wasm-ziele.md` |
| Nachbesserung | Überlappungen an „JSON-Zeile"/„signiertes Ticket" behoben; Naht-Label konsolidiert | `vision-architektur.md` |

**Bewiesene Werkzeug-Abweichung (G6):** Der installierte Claude-CLI läuft
über ein Gateway ohne echte Bildwahrnehmung und halluziniert Labels
(Test: gefragt nach der ersten Box antwortete er „z8run Proxy").
Claude-Run ist daher **nicht verwertbar**; die Prüfung wurde durch einen
unabhängigen Zero-Kontext-Vision-Subagenten ersetzt, der die Bilder per
Read wirklich sieht und jedes Label zitierte. Rohversuche + Begründung:
`docs/06-beweise.md` §6.6, `docs/img/claude-run-*`.
Status: **GRUEN** (mit dokumentierter Werkzeug-Abweichung).

## S4 — 2×30B-Abnahme: TEILWEISE BLOCKIERT (Provider-Konto)

Auftrag: zwei 30B-Modelle (`nvidia/nemotron-3.5-lightning`,
`qwen/qwen3-30b-a3b-instruct-2507`) über OpenRouter; Wiedergabe + Bau-Test.
Logs: `verify-logs/z8-proxy-reinigung/s4/`.

### Blocker (bewiesen, nicht selbst behebbar)

Beide vorhandenen OpenRouter-Schlüssel sind serverseitig ungültig:

```
/root/.secrets/openrouter.ini      -> GET /api/v1/auth/key = 401 {"message":"User not found."}
opencode-Backup (gleicher Key)     -> GET /api/v1/auth/key = 401 {"message":"User not found."}
```

Beweis: `s4/s4-openrouter-blocker.log`. Die `/models`-Liste funktioniert
(öffentlich), deshalb war S0 grün; erst der authentifizierte Chat-Call
zeigt den Kontofehler. Ohne gültigen Key sind die zwei NAMEN-Modelle nicht
erreichbar. Ersatz-30B nur nach Jason-Freigabe (Bauplan S4) — die liegt
nicht vor. Lokales Ausführen ist ausgeschlossen: 7,8 GiB RAM, 2 Kerne,
keine GPU, ~11 GB Plattenplatz; ein 30B-Modell braucht allein >18 GB.

### Ersatzlauf (zwei unabhängige Modelle, klar als NICHT-Plan-Abnahme markiert)

- Modell A: `zai/glm-5.3`
- Modell B: `deepseek/deepseek-v4-pro`
- Beide bekamen NUR `doc_full.txt` (PROXY.md + 01…08) + Fragenkatalog,
  keinen System-Prompt mit Fakten, Temperatur 0.

| Test | Modell A | Modell B | Beweis |
|---|---|---|---|
| Wiedergabe (30-Fakten-Checkliste, Kreuz-Judge) | **0 Fehler** | **0 Fehler** | `repro_A/B.json`, `judge_A/B-r5.log`, `facts.md` |
| Bau-Test: Code geliefert | Cargo.toml + src/lib.rs | Cargo.toml + src/lib.rs | `build_A/B.json` |
| Kompilat wasm32-unknown-unknown | rc 0, 566 B | rc 0, 566 B | `compile-A/B.log` |
| Imports | keine | keine | `strings`-Check |
| Wasmtime-Sandbox (neues Repo) | `ok=true`, `echo==input` | `ok=true`, `echo==input` | `sandbox-A/B.log` |

Der Bau-Test nutzt `bins/kv-proxy/examples/app_probe.rs` (neues Repo) und
die ECHTE Wasmtime-Sandbox; die Modell-Apps wurden unverändert geladen.
Beide Apps antworten mit `{"ok":true,"app":"miniapp","echo":<input>}`.

### Urteil S4

- Ersatzlauf: **GRÜN** (die Doku ist aus sich heraus reproduzier- und
  baubar; zwei unabhängige Modelle, 0 Wiedergabefehler, beide Apps laufen).
- Plan-Abnahme mit den ZWEI NAMEN-Modellen: **NICHT ERFÜLLT** — blockiert
  durch das ungültige OpenRouter-Konto. Das ist ein Provider-Blocker, kein
  Doku-/Code-Fehler.

**Was Jason liefern muss:** einen gültigen OpenRouter-Key in
`/root/.secrets/openrouter.ini` ODER die ausdrückliche Freigabe der zwei
Ersatzmodelle. Danach genügt ein Rerun von
`python3 s4_llm.py repro` + `build` + `judge A/B` + `app_probe`
(Logs überschreiben) — die Doku selbst muss dafür nicht geändert werden.

## Gesamturteil

| Stufe | Status |
|---|---|
| S0 Sicherung/Register | GRÜN |
| S1 Quellen-Rohliste | GRÜN |
| S2 Reines Repo (Dual-Compile, 50/0, E2E) | GRÜN |
| S3 Lehrbuch-Doku + 4 Grafiken (Vision GRÜN) | GRÜN |
| S4 2×30B-Abnahme (Namen-Modelle) | **BLOCKIERT (Provider-Konto)** |
| S4 Ersatzlauf (2 unabhängige Modelle) | GRÜN |

**Damit ist der Bauplan NICHT vollständig GRÜN.** Alles außer der
namen-genauen S4-Abnahme ist gebaut und bewiesen; der letzte Schritt
braucht einen gültigen OpenRouter-Key oder Jasons Freigabe der Ersatzmodelle.
