# Z8-WebAuthn-Login (Login v2)

Der KV3-Login authentifiziert den User mit **zwei Faktoren**:

1. **Passwort** → öffnet die Provider-Shard-Box (`kv3-open`).
2. **Besitz** → WebAuthn-Assertion (Software-Passkey) **oder** PEM
   (Hardware-/PEM-Parallelweg).

Der HW-Shard wird **ausschließlich clientseitig** geöffnet (ECDH P-256 +
ML-KEM-1024). Der Flow sieht nur den fertigen `shamir_hw`, nie einen
Privatekey und macht selbst kein ECDH.

## Nodes

### `webauthn-verify`

Prüft die Assertion gegen die publickey-Registry des Users, verbraucht die
Challenge (einmalig) und erhöht `sign_count`. Nur bei gültiger Assertion
wird der mitgelieferte `shamir_hw` akzeptiert und als `hw_block` an
`kv3-master` weitergereicht.

| Feld           | Default                        | Bedeutung                              |
|----------------|--------------------------------|----------------------------------------|
| `s3Config`     | `/etc/z8run/kv3-s3.json`       | S3-Zugang (Bucket/Prefix)              |
| `addrPath`     | `addr_user`                    | Adresse aus `kv3-adresse`              |
| `challengeDir` | `/data/z8run/login-challenges` | Einmal-Challenges (0600, 300 s TTL)    |
| `rpId`         | `localhost`                    | WebAuthn-Relying-Party                 |
| `origin`       | `http://localhost:7700`        | Erwartete `clientData.origin`          |

Fehlerfälle (alle auf den `error`-Port, HTTP 401 im Canvas):

- Challenge unbekannt/abgelaufen/verbraucht
- Signatur ungültig, `clientData.origin` falsch
- `sign_count` nicht gestiegen (Replay)
- Credential nicht registriert
- `key_type != webauthn-software` oder PQC-Pubkey fehlt → **klarer Hinweis
  auf den PEM-Weg**, kein stiller Fallback

### `webauthn-challenge`

Stellt die Einmal-Challenge aus und speichert sie serverseitig
(`challengeDir`, 0600). Wird im Login-Flow unter `POST /challenge`
veröffentlicht; derselbe Node wird bereits im Setup-Flow verwendet.

### `kv3-master` (Erweiterung)

Kombiniert Provider- und HW-Shard (Shamir 2-of-2) und liefert:

- `master_sha256` (Fingerprint, nur zum Abgleich)
- `session_view: {passkey_session_id, qr_code_uri}` für die spätere UI
- `proxy_session` (nur `unix-out`-Body, wird vor dem HTTP-Response entfernt)

### `unix-out` (Konsolidierung)

Der **WebAuthn-Login-Flow** nutzt `unix-out`: HTTP/1.1 über den lokalen
Proxy-Socket, `bodyPath=proxy_session`. `preserveInput=true` reicht die
Login-Antwort durch, `stripFields` entfernt `proxy_session`, `req`,
`opened_datei` und `uds_response` aus der HTTP-Antwort. Es gibt keinen
zweiten HTTP-Client und keinen TCP-Port. Der **alte PEM-Parallel-Flow**
behält aus Kompatibilität `kv3-socket`, strippt dort aber ebenfalls
`req`/`opened_datei`/`proxy_session`/PEM/KEM aus dem Output.

## Canvas / Hook-Pfade

`KV3-Login-WebAuthn` (`scripts/z8_webauthn_login_flow.py`):

```
POST /challenge   → webauthn-challenge → HTTP 200 {webauthn_challenge, rp_id, origin}
POST /login       → addr-space/addr-user → join → kv3-open
                  → webauthn-verify → kv3-master → unix-out (Proxy-Session)
                  → HTTP 200 (master_sha256, session_view) | HTTP 401
```

Login-Body:

```json
{
  "space": "z8wa", "user": "anna", "password": "...",
  "challenge": "...", "credentialId": "...", "authenticatorData": "...",
  "clientDataJSON": "...", "signature": "...",
  "shamir_hw": {"x": 2, "y_b64": "..."}
}
```

## Credential-Registrierung (Setup-Erweiterung)

`webauthn-register` akzeptiert zusätzlich `pqc_pub_b64` (ML-KEM-1024) und
schreibt:

- `b2b/<addr_user>-webauthn.json` — öffentliche Credential-Registry
  (`credential_id`, `pub_b64`, `pqc_pub_b64`, `sign_count`, `key_type`).
  **Nur Publickeys**, keine Secrets; der Login braucht keinen Setup-Master.
- einen zusätzlichen **hybriden v3-Block** in `workspaces/<addr>/hw-shards.txt`,
  versiegelt an Credential-P-256 (ECDH) ∥ Credential-ML-KEM-1024
  (Stahlgitter: `kette::umschlag::siegeln_v3`, beide Teile Pflicht).

Software-Passkeys erhalten `key_type=webauthn-software`. Hardware-Keys
ohne PQC landen als `webauthn-hardware` und werden beim WebAuthn-Login
abgewiesen (PEM-Weg).

## Client-Pflicht

Der Client (Agent/Browser) lädt `hw-shards.txt`, sucht seinen
Credential-Pubkey, öffnet die v3-Box lokal mit P-256-Privatschlüssel +
ML-KEM-1024-dk und schickt nur `{x, y_b64}`. Test-/Agent-Helfer:
`z8-stahlgitter shard-open --s3-config … --prefix … --addr … --key … --kem …`.

## MCP

`z8_login_challenge(user, space)` holt die Einmal-Challenge **vor** dem
Signieren. Danach `z8_login(space, user, password, assertion, shamir_hw)`
oder `z8_login(space, user, password, pem_path, pqc_dk_path)`.
`assertion` muss die zuvor geholte `challenge` enthalten (sonst klarer
Fehler statt stiller Neu-Challenge). PEM/KEM werden nur als Pfad unter den
Setup-Key-Verzeichnissen gelesen; das Tool gibt keine Privatekeys zurück.

## Beweise / Tests

- `verify-logs/z8-webauthn-login/s1-unit.log` — Assertion/Replay/Signatur/Hardware
- `s2-e2e.log` — echtes ES256-Ceremony-Paar, alle Negativfälle, PEM-Parallelweg, QR-SVG
- `s3-e2e.log` — CLI-/Server-Export mit gestopptem z8run, UDS-Session
- `s4-*.log` — MCP + 3× `cargo test`

## Abweichung (dokumentiert)

`webauthn-rs` wurde **nicht** zusätzlich eingeführt: Der Setup-Zweig besitzt
seit Z8SETUP einen geprüften ES256-Verifier (COSE/ES256, `clientData`,
`authData`, `sign_count`), der hier nativ wiederverwendet wird. Eine zweite
WebAuthn-Implementierung wäre eine Parallel-Implementierung desselben
Problems (G9) und hätte die bewiesene Setup-Logik dupliziert. Die
Ceremony-Paare in den Tests sind vollständige ES256-WebAuthn-Paare
(Register→Assert, echte `clientDataJSON`/`authData`/Counter).

## Antwort-Allowlist (kein Secret im HTTP-Out)

Der Login-Payload wird vor `http-out` bereinigt: `req` (enthält Passwort,
`key_pem`, `pqc_dk`, `shamir_hw`), `opened_datei` und `uds_response` werden
entfernt. `proxy_session` (inkl. `master_key_b64`) verlässt den Prozess
**nur** über `unix-out` an den Proxy-Socket; Event-Previews redachten
`master_key_b64`. Zusätzlich entfernen die Nodes die
verbrauchten Secret-Felder sofort aus `req.body` (`kv3-open`: Passwort,
`kv3-hwshard`: PEM/KEM, `webauthn-verify`: `shamir_hw`). Die Antwort
enthält nur Adressen, Salts, `master_sha256`-Fingerprint, `session_view`
und die Assertion-Metadaten.

## Challenge ist atomar

`setup_challenge::verbrauche` benennt die Challenge-Datei zuerst atomar um
und liest/validiert erst dann. Zwei parallele Aufrufe können dieselbe
Challenge nicht beide verbrauchen (kein read→remove-TOCTOU).

## Engine-Fix (Fehler-Routing)

Die Engine schloss Ziel-Kanäle bisher nach dem ersten Step, obwohl spätere
Nodes noch auf dasselbe Ziel (z. B. gemeinsames `err`-http-out) zeigen
konnten; Fehler leakten dann in den nächsten Output-Edge. Jetzt wird ein
Kanal erst geschlossen, wenn **alle** eingehenden Produzenten fertig sind.
Regressionstest: `engine::tests::spaeter_fehler_erreicht_shared_error_target`.
