# Z8-STAHLGITTER (Basis-Layer, 29.10.2026)

STAHLGITTER ist der Basis-Layer VOR jedem WebAuthn-Login-Bau: JEDE
asymmetrische Versiegelung im z8-KronVault-Bau ist hybrid (ECC P-256 +
ML-KEM-1024). Der klassische Nur-ECIES-Öffner existiert im z8-Zweig nicht
mehr — es gibt genau EIN Boxformat für neue Umschläge (v3) und keine
Rückfalltür. Passkey-/Assertion-Signaturen bleiben bis zur Hardware-
ML-DSA-Welle ES256 (flüchtige Challenges, lagern nichts).

## Beschluss-Block (Jason 29.10., D1–D6 ALLE FEST, wörtlich)

- **D1:** Boxen hybrid + Setup-Signaturen hybrid.
- **D2:** PQC über TRANSPORT (MCP-Verbindung) + Hybrid-Boxen. Passkey/
  Assertion-Signaturen bleiben ES256 (flüchtige Challenges, lagern
  nichts) bis Hardware-Keys ML-DSA können — dann EINE Migration für alle.
- **D3:** BIG BANG — alle Dev-Welten neu siegeln, klassischer Nur-ECIES-Öffner
  KOMPLETT entfernen. „Alles andere ist respektlos gegenüber der
  Sicherheitsdisziplin."
- **D4:** STAHLGITTER VOR jedem WebAuthn-Login-Bau (sonst Rework der
  Credential-Boxen).
- **D5:** Nur RustCrypto ml-kem/ml-dsa (auditiert, aktiv). Keine Exoten.
- **D6:** ML-KEM-1024 (hochgezogen von M6.5-768 — Jason-Entscheidung).

**Big-Bang-Begründung (D3):** Zwei parallele Formate wären eine dauerhafte
Rückfalltür und ein zweiter Öffner im Angriffsprofil. Ein einziger
Hybrid-Öffner ist beweisbar (nur-ECDSA und nur-PQC scheitern), während
Alt-Boxen nach der Migration nicht mehr öffenbar sind — genau das ist
gewollt.

## Umschlag v3 (EINE QUELLE: `tresor-proxy/src/umschlag.rs`)

```
{"v":3,
 "algo":"hybrid-ecc-p256-mlkem1024-hkdf-sha256-aes256gcm",
 "kem":"ML-KEM-1024",
 "ephem":b64, "kem_ct":b64(1568 B), "nonce":b64, "box":b64, "aad":str}
```

- ek = 1568 B, ct = 1568 B, dk = 3168 B (FIPS-203-Encodings).
- KDF: `HKDF-SHA256(ikm = ss_ecc || ss_kem,
  salt = ephem_pub || kem_ct, info = b"kv-m65-umschlag-v3")`.
- Öffnen verlangt **beide** Teile: ECC-Privatekey UND ML-KEM-1024-dk.
  Nur-klassisch, nur-PQC, falscher Teil, manipulierter `kem_ct` und
  v2-Felder unter v3 schlagen fehl (Unit-Tests + S1-Log).
- v1/v2 bleiben in der QUELLE lesbar (Hausmeister-Welt), der z8-Zweig
  nutzt sie nicht mehr.

## Identitäten und Schlüssel

- Jede Identität (Setup-Key, User-HW-Key) registriert ZWEI Publickeys:
  klassisch (P-256, SEC1-Base64) + ML-KEM-1024 (`pqc_pub_b64`).
- Setup-Keys tragen zusätzlich ein ML-DSA-87-Paar (`mldsa_pub_b64`,
  `setup-hwN-mldsa.pem`).
- Private PQC-Keys bleiben beim Halter: `<label>.kem` (Base64, 0600) neben
  dem PEM; Sidecar `<label>.kem.json` dokumentiert die Zuordnung.
  Welt2-Fixures tragen `pqc_keys` in `zugangsdaten/fixture.json`.

## Setup-Signaturen hybrid (S3)

Jeder Betriebsaufruf (`rotate`, `plugin`, `pubkey`, `webauthn-*`) braucht
weiterhin 2-of-N Setup-PEMs plus **zwei** Signaturen über
`<op>:<space>:<nonce>`:

- `setup_signature` — ECDSA P-256/SHA-256 (DER, Base64)
- `setup_mldsa_signature` — ML-DSA-87 (FIPS 204, Base64)
- `setup_pqc_keys` — die ML-KEM-1024-Privatekeys der beteiligten PEMs

Fehlt eine der beiden Signaturen, ist eine falsch, oder fehlt der
registrierte ML-DSA-Pubkey → **403**, nie still. Beweis:
`verify-logs/z8-stahlgitter/s3-operation.log`.

## BIG BANG / Migration

`z8-stahlgitter migrate` (Binary, kein Python-Krypto) arbeitet je Box:

1. Halter-PEM zum Ziel-Pubkey suchen, ML-KEM-1024-Paar erzeugen (falls
   nicht vorhanden) und beim Halter ablegen.
2. Alt-Box öffnen (v1/v2 nur im Migrationswerkzeug), Klartext prüfen.
3. Hybrid v3 an dieselbe Identität mit demselben AAD neu siegeln.
4. Gegenöffnen als Gültigkeitsbeweis, dann gleiches S3-Objekt ersetzen.
5. Master/Shards/Salts/DBs bleiben unverändert (nur die Versiegelung
   ändert sich).

`z8-stahlgitter verify` ist die Gegenprobe: jede asymmetrische Box muss
v3/ML-KEM-1024 mit 1568-B-Ciphertext sein; v1/v2 = Fehler.

### Historische Testarchive (dokumentierte Abweichung)

14 superseded Test-Prefixe (`run1`…`run8-rot`, `final10`…`final12`) hatten
keine überlebenden Halter-PEMs mehr (die Testläufe überschrieben ihre
Key-Verzeichnisse; Responses wurden nicht archiviert). Ihre Boxen sind
damit kryptografisch nicht mehr zu öffnen und nicht regelkonform
neu zu siegeln. Unter D3 („keine zwei Formate") wurden sie nach lokalem
Backup (`z8run-test/backups/z8-stahlgitter/legacy-unmigriert/`) aus dem
aktiven S3-Namespace entfernt; Log:
`verify-logs/z8-stahlgitter/s2-quarantaene.log`. Die kanonischen Welten
(Welt2-Sim, gamma/archive15+16, final13/14, run9, frischer Setup-Bau)
sind vollständig v3 migriert/gebaut. Ein verwaister, per `/user-pubkey-add`
angehängter Zusatz-Pubkey in archive16 (Halter-Key nie ausgeliefert)
wurde als einzige Box entfernt; die Identität bleibt mit den zwei
Original-HW-Keys vollständig.

## Betrieb (MCP + Binary)

```bash
# Migration + Gegenprobe
z8-stahlgitter migrate --s3-config /etc/z8run/kv3-s3.json \
  --prefix sim2/welt2/ --keys <key-dir>... --local <welt-dir>... \
  --report report.json
z8-stahlgitter verify  ...        # Exit 0 = keine Alt-Box mehr

# Login-Gegenprobe Welt2 (Master vor == nach)
z8-stahlgitter world2 --dir /data/kronvault/kronvault-bucket-konzept/welt2
```

MCP: `z8_stahlgitter(action=migrate|verify, keys=[...], local=[...])`.
Das Tool ruft ausschließlich das Binary und liefert Hashes/Pubkeys —
niemals Privatekeys.

## Transport-Vermerk (D2)

Der MCP-Agent-Zugang läuft lokal über Unix-Socket/HTTP; der PQC-Transport
(TLS-Handshake mit ML-KEM-Gruppe, Endpoint-Ebene) ist als eigener
Folgeplan vorgemerkt. Der Handshake-Hook muss den PQC-Status loggen
(`pqc=mlkem1024` vs. `pqc=classic`); Boxen sind davon unabhängig bereits
hybrid.

## Beweise (Rohlogs)

| Stufe | Log |
|-------|-----|
| S0 | `verify-logs/z8-stahlgitter/s0-s3-inventory.txt` |
| S1 | `s1-unit.log` (v3-Roundtrip, Hybrid-Zwang, v2-Felder) |
| S2 | `s2-migration.log`, `s2-verify.log`, `s2-world2-login.log`, `s2-quarantaene.log` |
| S3 | `s3-operation.log` (positiv + alle Negativfälle) |
| S4 | `s4-export-*.log`, `s4-verify-world.log`, `s4-fresh-verify.log`, `s4-verify-rotated.log` |
| S5 | `s5-cargo-test-{1,2,3}.log`, `s5-mcp.log` |
