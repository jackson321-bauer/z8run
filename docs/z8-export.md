# z8-export — Flows als eigenständige Programme

`z8-export` macht aus einem gespeicherten Flow ein **eigenständiges
Cargo-Projekt** und optional eine fertige Binary. Die Binary braucht
**keinen laufenden z8run-Server**: sie baut das Flow-Objekt aus dem
Canvas-JSON und ruft die **echte `FlowEngine`** aus `z8run-core` auf.

Es wird **keine Node-Logik nachgebaut**. Das generierte Projekt hängt per
`path`-Dependency am echten Quellbaum:

```toml
[dependencies]
z8run-core = { path = "/data/z8run-test/src/crates/z8run-core" }
```

`cargo tree` im generierten Projekt zeigt diese Kante; über die
generierten `.rs`-Dateien ist `grep "fn process"` leer.

## Voraussetzungen

- Rust-Toolchain (`cargo`, `rustc`).
- Der Quellbaum mit `crates/z8run-core` (Standard: der Baum, in dem
  `z8-export` gebaut wurde; überschreibbar mit `--core-path`).
- Für `--target wasm`: `rustup target add wasm32-wasip1` und `wasmtime`.

## Aufruf

```bash
# aus der Datenbank
z8-export --db /data/z8run/data/z8run.db \
          --flow-id 01a184da-a921-75e4-b3dd-52e2b31713ac \
          --out ./kv3-setup --mode cli --build

# aus einer Flow-JSON (gespeicherter Flow oder API-Export)
z8-export --flow-file flow.json --out ./myflow --mode cli --build
```

| Option | Default | Bedeutung |
|--------|---------|-----------|
| `--flow-file` | — | Flow-JSON (Alternative zu `--db`/`--flow-id`) |
| `--db` / `--flow-id` | — | Flow aus der z8run-SQLite-Datenbank |
| `--out` | `./z8-export-out` | Zielverzeichnis des Projekts |
| `--mode` | `cli` | `cli` (stdin → stdout) oder `server` (Mini-axum) |
| `--target` | `native` | `native` oder `wasm` (nur Logik-Flows) |
| `--build` | aus | `cargo build` direkt ausführen |
| `--readable` | aus | lesbare Namen + Debug-Build (nur Entwicklung) |
| `--core-path` | Build-Baum | Pfad zu `crates/z8run-core` |

Der Befehl gibt JSON aus: Projektpfad, Binary, Trigger, Modus, Ziel.

## Drei Befehle für Endnutzer

```bash
# 1) Flow exportieren und bauen
z8-export --db /data/z8run/data/z8run.db --flow-id <FLOW-ID> \
          --out ./mein-flow --mode cli --build

# 2) Binary ohne z8run starten (stdin = Trigger-Body)
echo '{"space":"space-alpha"}' | ./mein-flow/target/release/<binary>

# 3) Server-Variante exportieren, bauen und starten
z8-export --db /data/z8run/data/z8run.db --flow-id <FLOW-ID> \
          --out ./mein-flow-server --mode server --build
./mein-flow-server/target/release/<binary>    # bindet 127.0.0.1:8080
# Route = Trigger-Pfad, z.B.:
curl -X POST http://127.0.0.1:8080/setup -d '{"space":"space-alpha"}'
```

## CLI-Modus

Die Binary liest den Trigger-Body als **erstes Argument** oder von **stdin**
(JSON; sonst Rohtext) und schreibt die Antwort des `http-out`-Nodes als JSON
nach **stdout**.

- Exit `0`: Antwortstatus < 400 **und** kein `error`-Feld im Body.
- Exit `1`: Fehlerstatus, `error`-Feld oder kein `http-out` erreicht.

Der Trigger-Payload ist exakt das Hook-Format:
`{method, path, headers, query, body}`.

## Server-Modus

Mini-axum mit **einer Route pro Trigger** (`method` + `path` aus dem
Canvas). Der HTTP-Status kommt aus `statusCode` des `http-out`-Nodes.
Bind-Adresse: `Z8_EXPORT_BIND` (Default `127.0.0.1:8080`).

## Secrets

Der Export bricht ab, wenn das Flow-Dokument irgendwo einen
**Klartext-Secret** enthält. Geprüft werden Schlüsselmuster wie `secret`,
`password`, `access_key`, `api_key`, `private_key`, `key_pem`, `token`,
`authorization`, `credential` — über Canvas-Configs, die Top-Level-Node-Liste
und `env_vars`. Erlaubt sind Referenzen:

- `"vault:mein_key"` → zur Laufzeit `Z8_SECRET_MEIN_KEY`
- `"$ENV:MEIN_KEY"` → zur Laufzeit `MEIN_KEY`

Fehlt die Umgebungsvariable, bricht die Binary mit klarer Meldung ab.
Im generierten Projekt steht **kein** Klartext-Secret.

Pfad-Felder wie `passwordPath` oder `tokenPath` zeigen auf Request-Daten
und sind keine Secrets; sie werden nicht blockiert. `${NAME}` wird NICHT
aufgelöst und gilt deshalb als Klartext (nur `vault:` und `$ENV:` sind
Referenzen).

## Obfuscation

Standard: verstümmelte Config-Dateinamen, generierte Funktionssymbole und
gehashte Package-Namen sowie `release` + LTO + `strip`. Der Binary-Name
bleibt lesbar (`z8_<FlowName>`), damit Endnutzer ihn starten können.
`--readable` erzeugt lesbare Namen und einen Debug-Build — nur Entwicklung.

Der `z8run-core`-Anteil bleibt unverändert (er ist Teil der
path-Dependency, nicht des generierten Teils).

## WASM

`--target wasm` baut dieselbe Verkabelung für `wasm32-wasip1`. Erlaubt
sind nur Logik-Nodes (Function, Join, Switch, Mapper, JSON, Filter,
Delay, …). Trigger- und Terminal-Nodes (`http-in`, `unix-in`, `http-out`)
bleiben erlaubt: sie bilden nur Request-Format und Antwort ab, keinen
Netz-Transport. Echte Netz-/DB-Nodes sowie die KV3-Crypto-Nodes werden
**je Node** mit klarer Fehlermeldung abgelehnt, nie still übergangen.
Reine Hash-/HMAC-Logik (`sanitize`, `webhook`) bleibt erlaubt.

```bash
z8-export --flow-file logic.json --out ./logic --target wasm --build
echo '{"msg":"hallo"}' | wasmtime run ./logic/target/wasm32-wasip1/release/<binary>.wasm
```

Der WASM-Lauf liefert dasselbe Ergebnis wie der native CLI-Lauf.

## MCP

Das Tool `z8_export_flow` in `/data/z8run/mcp/z8run_mcp.py` ruft die CLI
auf und liefert Projekt, Binary, SHA-256 und optional den Binary-Lauf:

```json
{"flow_id": "...", "target": "native", "mode": "cli",
 "build": true, "input_json": {"space": "space-alpha"}}
```

`z8_export_document` bleibt der reine JSON-Export über die REST-API.

## Generierte Dateien

```
flow.json          Canvas ohne Node-Configs (Graph + Metadaten)
config/<name>.json je Node eine Config (verstümmelter Name)
src/main.rs        Trigger-Adapter → canvas_to_flow → echte FlowEngine
Cargo.toml         path-Dependency auf z8run-core
```

## Referenz-Beweis (Login-Kette)

`bins/z8-export/scripts/kette_ref.py` rechnet die Login-Kette unabhängig
nach (Argon2id, AES-GCM, ECIES-P256, Shamir 2-of-2) und vergleicht mit der
Fixture. Es bestätigt: `sha256(master)` == Flow-Ausgabe, `hex(master)` ==
Fixture-Feld.

```bash
/root/hermes-venv/bin/python3 bins/z8-export/scripts/kette_ref.py \
  space-alpha anna anna-test-1 \
  /data/kronvault/kronvault-bucket-konzept/welt2/keys/anna-hw1.pem
```

## Grenzen

- Ein Export = ein Trigger (CLI) bzw. alle Trigger des Flows (Server).
- Kein LLVM-Obfuscator, keine eigene Historie/OTel im Export.
- WASM ohne Netz-/DB-Nodes.
