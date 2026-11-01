# Z8-Plattform-Kern (verbindlich)

Stand: Z8-Grundreinigung, 02.11.2026. Diese Datei ist die Wahrheit für
Nodes, Flows, Setup-Engine und Quorum. Abweichungen sind hier zu ändern,
bevor Code geändert wird.

## 1. Setup = eigene Engine

`bins/z8-setup` ist die Setup-ENGINE (standalone, kein z8-Flow nötig).
Sie importiert `z8run_core::nodes::setup_nodes::setup_kern` — DASSELBE
Modul wie der Flow-Node `setup-engine`. Kein Parallelcode.

```
z8-setup init --space NAME --user name:passwort \
  --providers-config /etc/z8run/s3-multi-providers.json \
  --bucket BUCKET --prefix P/
z8-setup health  --providers-config ... --bucket BUCKET
z8-setup put     --key obj --file lokal
z8-setup replicas --key obj
```

Erzeugt: Setup-PEMs (Shamir 2-of-N, ML-DSA), User-PEMs + ML-KEM-1024,
Passbox (`Argon2IDHashDatei/3`, `b2b/<addr>.txt`), HW-Shards
(`workspaces/<addr>/hw-shards.txt`, hybrid v3), DBs (Z8FC1+WAL+FTS5+vec0),
Escrow, verschlüsselte Registry. Der Flow `Z8-Setup` ist ein dünner
Wrapper (`unix-in -> setup-engine -> setup-summary -> http-out`).

## 2. Provider und Quorum

Wahrheit: `s3-multi-providers.json` (0400/0640, NIE im Repo). Format:
`{ "<name>": {"endpoint","region","access_key","secret_key"} }` plus
`bucket`, `prefix`, `quorum_min`.

- Produktiv nur Linode (de-fra-1), Impossible-Cloud (eu-central-2),
  DigitalOcean (fra1). DanubeData hat NULL Rolle.
- Jeder Write geht an ALLE Provider. Zwangsquorum `quorum_min` (Default 2).
  Unter dem Quorum: Vorflug-HEAD schlägt fehl, es wird NICHTS geschrieben
  (fail-closed, kein Teilzustand). Über dem Quorum mit Einzelausfall:
  Write geht weiter, `provider_degraded=true`; der nächste Write desselben
  Keys schreibt wieder an alle (Heilung).
- Lesen: erster antwortender Provider; Hashes aller Replikate sind gleich
  (`z8-setup replicas --key ...`).

## 3. Login /3 (Browser + nativ)

- Format `Argon2IDHashDatei/3`; Adresse = Argon2id(Name, Salt), Salt =
  sha256("kv3-salt:"+space) bzw. sha256(salt_space+":user:"+name).
- Browser (`crates/z8run-browser`): `/3`-only. B2B-Datei + hw-shards kommen
  aus S3; Passbox (Argon2id+AES-256-GCM) + HW-Box v3 hybrid (P-256 +
  ML-KEM-1024, EINE Quelle `tresor-proxy/umschlag.rs`) → Master.
- `Hashdatei /2` existiert nicht mehr (410 am 443-Front).
- WebAuthn-Login (Faktor 2): Flow `KV3-Login-WebAuthn`, Hooks
  `/hook/<id>/challenge` und `/hook/<id>/login`. Der Client öffnet den
  HW-Shard lokal und liefert `shamir_hw`; der Kern prüft ES256-Assertion,
  Challenge (Einmal), Origin, RP-ID und Sign-Counter. Danach Übergabe an
  den Proxy über udsv3; Antwort enthält Proxy-Token.
- Logout HART: Tokens tot, Session+Master zeroize, Worker fail-closed.

## 4. Flows (Endliste)

BLEIBEN (7):
- `Z8-Setup`, `Z8-Setup-Operation`, `Z8-Setup-WebAuthn`
- `KV3-Setup`
- `KV3-Login-WebAuthn`
- `Z8-PROXY`
- `Z8-OTEL`

GELÖSCHT: `KV-Login`, `KV-Login-Proxy`, `KV-Proxy`, `Kronvault-Engine`,
`Proxy-Engine`, `KV3-Login` (PEM), `test`, `Z8-STREAM`, `Z8-BLOB-E2E`.

## 5. Nodes

GELÖSCHT (Selbstbau-Leichen): `kv-login`, `kv-derive`, `pem-gen`,
`shamir-split2`, `passbox-seal`, `hwbox-seal`.

BLEIBEN (Plattform): `setup-engine`, `setup-summary`, `setup-result`,
`setup-auth`, `setup-validate`, `setup-keygen`, `setup-world`, `rotate-s3`,
`plugin-add`, `user-pubkey-add`, `webauthn-challenge`,
`webauthn-register`, `webauthn-assert`, `webauthn-verify`, `kv3-adresse`,
`kv3-open`, `kv3-master`, `kv3-socket`, `kv-proxy`, `kv-otel`, `kv-stream`,
`kv-export`, `db-query`, `blob-put`, `blob-delete`, `s3-db-fetch`,
`sqlite-exec`, `unix-in`, `unix-out`, `http-out`, `http-request`, `join`,
`switch`, `debug` — plus ALLE z8-Standard-Nodes.

## 6. Secrets

Keys/URLs nur in der Gateway-/Provider-Config. Keine Klartext-Keys in
Registry (verschlüsselt), Logs oder Repo. Session-Master nur im RAM/UDS.
