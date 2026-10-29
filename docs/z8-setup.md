# Z8-Setup (API 0)

Die Setup-API ist ein z8-Flow, der als eigenständige Binary exportiert wird.
Sie baut die lokale Welt (Space + N Userspaces), erzeugt Setup-Keys und
erledigt danach alle schreibenden Änderungen **nur mit Setup-Key**.
Kein z8run-Server, kein Managed-Sync, keine Shared-Datenbanken (D6).

## Flows und Endpunkte (Unix-Socket)

| Flow | Pfad | Auth |
|------|------|------|
| `Z8-Setup` | `POST /setup` | nur wenn Welt noch nicht existiert |
| `Z8-Setup-Operation` | `POST /rotate-s3` | Setup-Key + Signatur |
| | `POST /plugin-add` | Setup-Key + Signatur |
| | `POST /user-pubkey-add` | Setup-Key + Signatur |
| `Z8-Setup-WebAuthn` | `POST /webauthn/challenge` | lokal |
| | `POST /webauthn/register` | Setup-Key + Signatur |
| | `POST /webauthn/assert` | Setup-Key + Signatur |

Hook-URL: `/hook/<flow-id><pfad>` über `/data/z8run/z8run.sock`.
`scripts/z8setup_flows.py` legt die Canvases an/aktualisiert sie.

## Schlüssel

- `setup-keygen` erzeugt einen Setup-Master (32 B) und teilt ihn per
  **Shamir 2-of-N** auf N Setup-PEMs. Die PEMs werden per API ausgegeben
  und zusätzlich unter `/data/z8run/setup-keys/<space>/` (0600) abgelegt.
- Die **Setup-Registry** liegt nur verschlüsselt im S3 (AES-GCM, Schlüssel
  aus dem Setup-Master). Sie enthält Setup-Pubkeys, User-Pubkeys, Workspace-
  Pfade und die S3-Zugangsdaten — alles at-rest verschlüsselt.
- Je User: eigener Master (32 B), Shamir 2-of-2 in Provider-Shard
  (Passwort-Box, Argon2id + Salt) und HW-Shard (ECIES an den User-PEM).
- **Escrow:** Der HW-Shard wird zusätzlich mit dem Setup-Master versiegelt
  (`setup/escrow/<addr>.txt`), damit `/user-pubkey-add` später an einen
  neuen Pubkey resharden kann. Das ist kein Privatekey des Users, sondern
  der verschlüsselte Share (Hausmeister-Prinzip D1/D2). Bedrohungsmodell:
  Der Share allein öffnet nichts; erst Setup-Master **und** User-Passwort
  zusammen ergeben einen Master. Die Datei ist at-rest verschlüsselt.
- **Private User-PEMs** werden nur lokal unter
  `/data/z8run/setup-keys/<space>/users/` (0600) geschrieben und **nicht**
  in S3/Registry gespeichert; die API liefert nur `path` + `pub_b64`.
  Setup-PEMs werden gemäß D2 zusätzlich im Response ausgegeben.
- Setup-Hardwarekeys und User-Hardwarekeys sind getrennte PEM-Sätze;
  Setup-Keys werden nie als Produktions-User-Keys verwendet.

## Dateiformat und S3-Layout

Format `Argon2IDHashDatei/3` (identisch zu seed_welt2/kette):

```
Argon2IDHashDatei/3
wirt_min = 1.4.0
nr = 1

Secretboxes
Anfang
<adresse> = Block-1
Ende

Encrypted
Anfang
Block-1
<base64(JSON-Box)>
Ende
```

- `b2b/<addr_user>.txt` — Passwort-Box (Provider-Shard, Engines, DB-Metadaten)
- `workspaces/<addr_user>/hw-shards.txt` — ECIES-Boxen je HW-Pubkey
- `workspaces/<addr_user>/db/{demo,meta}.db` — SQLCipher-DBs
- `setup/registry.txt`, `setup/setup-shards.txt`, `setup/escrow/<addr>.txt`

Salts (fest pro Space): `sha256("kv3-salt:"+space)`, daraus
`sha256(salt+":user:"+name)`. Adresse = `argon2id(name,salt)` → Base32[0..32].

## Datenbanken

`setup-db` erzeugt je User `demo.db` und `meta.db` mit **SQLCipher + WAL +
FTS5 + vec0** (`vec0Path`, Default `/data/z8run/vec0.so`), inklusive
RAM-Offload-PRAGMAs (`cache_size=-65536`, `mmap_size`). Der DB-Key wird aus
dem User-Master abgeleitet, im User-Block versiegelt und **nicht** in der
API-Antwort ausgegeben. Der Inhalts-Hash steht in der Hashdatei/Registry.

## WebAuthn / FIDO2

Attestation `fmt=none`, ES256 (P-256). Die Challenge wird serverseitig
unter `/data/z8run/setup-challenges` (0600, 300 s TTL) gespeichert und bei
Registrierung/Assertion **einmalig verbraucht**. `webauthn-register` prüft
clientData (`webauthn.create`, Challenge, Origin), rpIdHash, Flags
(UP+AT), Credential-ID und COSE-Pubkey; das Credential wird in der
verschlüsselten Registry gespeichert. `webauthn-assert` prüft
`authData||sha256(clientDataJSON)` gegen den gespeicherten Pubkey und
zählt `sign_count` hoch. Die Adaptierung in den Login-Flow ist ein eigener
Folge-Bauplan (hier nur Einrichtung + Assertion-Beweis).

## Rotation (`/rotate-s3`)

Nimmt `newS3` (host/region/bucket/prefix/access_key/secret_key) entgegen,
kopiert alle Objekte in das neue Ziel, schreibt die Registry mit den neuen
S3-Daten neu und löscht optional (`deleteOld`) die alten Objekte.
**Shards, Salts und Master bleiben unverändert** — Login mit altem Passwort
und altem PEM funktioniert gegen die neuen Dateien (Beweis: gleicher
`user_master_sha256`).

Mit `"rotateBoxes": true` + `userPasswords: {name: passwort}` werden die
Boxen **wirklich neu versiegelt** (neue Nonces/Ephemeral-Keys): User-Box mit
demselben Passwort/Salt, Setup-Plugin-Box mit dem Setup-Master, HW-Boxen
mit dem Escrow-Share an jeden User-Pubkey. Ohne Passwörter ist es eine
S3-Relocation (Boxen byte-identisch); mit Passwörtern ändern sich die
Ciphertexte, der Master bleibt gleich.

## Plugin-Freigabe (`/plugin-add`)

Fügt in der User-Hashdatei einen **setup-versiegelten** Block
`setup-plugins-<addr>` hinzu. Der User-Block bleibt unberührt; die
Freigabe ist nur mit Setup-Master möglich (D5).

## Pubkey-Erweiterung (`/user-pubkey-add`)

Öffnet den Escrow-Share mit dem Setup-Master, versiegelt ihn an den neuen
HW-Pubkey und hängt einen Block an `hw-shards.txt`. Vorbereitung für
Resharding; der neue Pubkey wird in der Registry geführt.

## Signatur der Betriebsaufrufe

Jeder Betriebsaufruf braucht mindestens **2 Setup-PEMs**, die zusammen den
Setup-Master rekonstruieren (2-of-N-Quorum), und eine ECDSA-P-256-Signatur
des ersten PEM über:

```
<op>:<space>:<nonce>
```

`op` = `rotate` | `plugin` | `pubkey` | `webauthn-register` | `webauthn-assert`.
Felder: `setup_pems` (Array), `setup_signed`, `setup_signature` (Base64 DER).
Ohne/mit falschem Key → **403**, nie still. Das Quorum ist „Besitz von 2
Keys“ (Master-Rekonstruktion); signiert wird mit einem der beiden.

## Export und Betrieb ohne z8run

```bash
# 1) Setup-Flow als Server-Binary
z8-export --db /data/z8run/data/z8run.db --flow-id <Z8-Setup-ID> \
  --out ./z8setup --mode server --build

# 2) Welt bauen — NUR über Unix-Socket (D3), z8run darf gestoppt sein
Z8_EXPORT_SOCK=/data/z8run/setup.sock ./z8setup/target/release/z8_Z8_Setup &
curl --unix-socket /data/z8run/setup.sock -X POST http://localhost/setup -d @setup.json

# 3) Rotation
z8-export --db /data/z8run/data/z8run.db --flow-id <Operation-ID> \
  --out ./z8setup-op --mode server --build
Z8_EXPORT_SOCK=/data/z8run/setup-op.sock ./z8setup-op/target/release/z8_Z8_Setup_Operation &
curl --unix-socket /data/z8run/setup-op.sock -X POST http://localhost/rotate-s3 -d @rotate.json
```

## MCP

`z8_setup(action=initial|rotate|plugin|pubkey, …)` im MCP-Bridge
(`bins/z8-export/mcp/z8_setup_run.py`, installiert unter `/data/z8run/mcp`).
Setup-PEMs werden ausschließlich als **Pfade** unter
`/etc/z8run/setup-keys` oder `/data/z8run/setup-keys` übergeben; das Tool
signiert lokal und redigiert PEM-Inhalte aus der Antwort.

## Abhängigkeiten

Die Krypto-/S3-Wahrheit liegt außerhalb dieses Repos als path-Dependency:
`/data/kronvault/kv-login` (kette.rs) und `/data/kronvault/kv-store`
(SigV4). Beide werden mit dem lokalen Worktree-Stand gebaut; für
Reproduzierbarkeit sind die Commit-Hashes im VERIFY-Bericht dokumentiert.

## Grenzen

- Lokal/Single only; mehrere Userspaces am selben PC, aber **kein
  DB-Sharing** zwischen Usern (D6).
- Kein Managed-Betrieb, keine Transfer-Buckets, kein Sync.
- Kopfzeilen-/PEM-Format: SEC1 mit explizitem `prime256v1`-Parameter
  (OpenSSL- und Rust-kompatibel).
- Der Setup-Flow ist Einmal-Initialisierung pro Space-Prefix; eine
  existierende Registry führt zu HTTP 400 mit der Ursache
  „bereits initialisiert“ (intern 409, der 400-Sink vereinheitlicht).
- Die exportierte Server-Binary lauscht nur dann ausschließlich auf UDS,
  wenn `Z8_EXPORT_SOCK` gesetzt ist. Für die Setup-API ist das Pflicht.
