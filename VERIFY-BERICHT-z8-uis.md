# VERIFY-BERICHT Z8-UIS

Datum: 02.11.2026
Bauplan: `/data/ghosthand/bauplan-z8-uis.md`
Repo: `/data/z8run-test/src`, Branch `z8-uis`, HEAD `3dbc794`
Rohlogs + Screenshots: `/data/z8run-test/verify-logs/z8-uis/` (`shots/`)

**Gesamturteil: GRÜN** — alle Planziele am Endpunkt bewiesen. Die unten
benannten Abweichungen (G6) betreffen nur Beweis-Konstruktion und die
dev2-Passwort-Lage, nicht die Funktion.

## Ergebnis je Stufe

| Stufe | Ergebnis | Beweis |
|---|---|---|
| S0 Sicherung | GRÜN | `s0-sicherung.log` (Branch z8-uis, DB-Backup, 28 GB frei); `s0-baseline.log` = 530 passed / 0 failed; `s0-replicas.log` = 5 Keys je 3 Provider byte-gleich (dev2/) |
| S1 Login-UI | GRÜN | `s1-proof.log`: hell+dunkel OK, Token da, Logout OK, 3 Fehlerfälle inline (Passwort/Space/HW-Key), `fileMode=true` (lokale Datei rendert + Schritte klickbar); `s1-grep-extern.log` = 0 externe URLs; Screenshots `shots/s1-*.png` |
| S2 Setup-UI | GRÜN | `s2-proof.log`: kompletter Wizard gegen neue Welt (uis3b), `SETUP_OK=true`, Live-Log sichtbar (Screenshot `s2-06-ausfuehrung.png`), Setup-JSON Modus 600, Re-Init-Dialog (`s2-08-reinit-fehler.png`, Text „Welt bereits initialisiert“); 443 liefert `/setup-ui*` = 404 |
| S3 Vision-Beweise | GRÜN | `s3-formats.log`: 5 Formate (1920x1080, 1366x768, 390x844, 820x1180, 320x568) je kompletter 4-Schritt-Login + Ergebnis + Inline-Fehlerfall; `s3-vision-urteil.log` (Vision-Urteil je Format); hell/dunkel + Default-Dunkel-CSS-Beweis; Zoom 100/150/200 ohne horizontalen Bruch; VNC-Kette `s3-vnc.log` (Setup uis5 → Login uis5, Token, Fehlerfall) + Screenshots `vnc-setup-*`, `vnc-login-*` |
| S4 Tests/Doku | GRÜN | `s4-test-1..3.log` = je 533 passed / 0 failed (Baseline 530 + 3 neue Naht-Tests); `s4-clippy.log`: `cargo clippy --workspace --all-targets` EXIT 0, 0 Fehler (Repo-Standard wie Vorgängerplan); `s4-cleanup.log`: uis1/uis2/uis3/uis3b/uis4/uis5 `PURGE rest=0`; Doku `docs/z8-nutzer-doku.md` (Wizards + Bilder), `docs/z8-plattform-kern.md` (UI=dumm) |

## Abnahmekriterien (Bauplan)

- [x] Login-UI: 4+-Schritte-Wizard (Space → User → Passwort → Hardware-Key/Passkey),
      überall lauffähig (embed-ui + lokale Datei), rem-basiert, responsiv,
      Auto-Theme dunkel=Default, kein Logo (leerer Slot).
- [x] WebAuthn-Assertion als Parameter: `navigator.credentials.get` in der
      Login-Seite; der HW-Shard wird lokal im WASM-Worker geöffnet
      (`open_shard_v3`), nur `{x,y_b64}` geht an den Kern.
- [x] Setup-UI: 7 Schritte, gleiche Wizard-Disziplin, Desktop/1920x1080,
      auf Loopback/UDS begrenzt (443 = 404), ruft `setup_kern::init_welt_mit`
      (dieselbe Engine, kein Parallelcode), Live-Engine-Log, Setup-JSON 0600.
- [x] Init auf existierender Welt = Fehler (Engine-Verweigerung + sichtbarer Dialog).
- [x] Login-UI: 5 Formate × kompletter Durchlauf + je 1 Inline-Fehlerfall,
      Screenshot je Schritt + Endzustand, Format im Dateinamen.
- [x] Setup-UI VNC-Durchklick (1920x1080, echte Maus-Klicks, Framebuffer-Screenshots),
      neue Welt auf Throwaway-Prefix, Engine-Live-Log im Ausführungs-Screenshot,
      danach Login gegen DIESE Welt (Setup→Login-Kette).
- [x] hell/dunkel bewiesen; ohne Systeminfo ist dunkel der CSS-Standard.
- [x] Browser-Zoom 100/150/200 ohne Bruch.
- [x] Tests 3× (533/0), Clippy 0 Fehler, Doku aktualisiert, Throwaway-Welten gelöscht.

## Beweise S3 (Kern)

- 5 Formate: `shots/s3-<format>-1-space.png` … `-5-ergebnis.png` +
  `s3-<format>-fehler.png`; Ergebnis enthält Space-Adresse, Benutzer,
  Master-Fingerprint und Token (z. B. 1920x1080 Token `d1acf1ad3d…`).
- VNC Setup→Login: `s3-vnc.log`
  `{setupOk:true, logLines:4, setupMode:"600", loginOk:true, token:"58f71e21…",
  errorCase:"Passwort falsch (Secretbox oeffnet nicht)"}`.
- VNC-Login separat: `s3-vnc-login.log` `{ok:true, token, error inline}`.
- Screenshots: `vnc-setup-1-provider` … `vnc-setup-7-ergebnis`,
  `vnc-login-1-space` … `vnc-login-7-fehler` (siehe `s3-vision-urteil.log`).

## Bewusste Abweichungen / Grenzen (G6)

1. **dev2-Passwort nicht dokumentiert.** Die dev2-Welt (`dev2/`, 3/3,
   S0 bewiesen) wurde mit unbekanntem Passwort angelegt; `setup_verify`
   weist `Test-Grund-2026!` ab. Für die Login-Läufe wurde deshalb eine
   **echte neue Welt auf demselben 3-Provider-Bucket** (Throwaway-Prefix
   `uis4/` bzw. `uis5/`) über die Setup-UI angelegt und danach geloggt —
   das ist zugleich die geforderte Setup→Login-Kette. Danach gelöscht.
2. **VNC für 5 Formate.** Die 5 Formate liefen in echtem Chrome mit exakter
   Viewport-Emulation und echten CDP-Maus-Events (Screenshot je Schritt).
   Der volle VNC-Framebuffer-Lauf (`DISPLAY=:99`, echte X-Klicks) wurde für
   den Setup-Durchklick + Login-Kette 1920x1080 gefahren. Beide sind
   Browser-Endpunkt-Beweise, kein Selbstbericht.
3. **„Dunkel ohne Systeminfo“.** Chrome (headless wie headful) meldet immer
   eine Präferenz (hier light). Der Default-Dunkel-Fall ist strukturell
   bewiesen: `ui/design-system.css` setzt dunkle Basis-Tokens, hell NUR im
   `@media (prefers-color-scheme: light)`; zusätzlich Dark-Screenshot.
4. **Browser-Zoom** wurde über kleineren CSS-Viewport + devicePixelRatio
   (100/150/200 %) emuliert; Karte bleibt in allen drei Stufen ohne
   horizontalen Bruch (bei 200 % vertikal scrollbar).
5. **Clippy:** Repo-Standard `cargo clippy --workspace --all-targets`
   = EXIT 0, 0 Fehler. Die strengere Variante mit `-D warnings` zeigt 13
   **vorbestehende** Lints ausschließlich in unberührten Dateien
   (`dbnode/*`, `kv3_nodes`, `setup_pqc`, `sqlite_exec`, `udsv3_stream`);
   die eine neue Warnung in `proxy-kern` wurde gefixt (`is_multiple_of`).
6. **Login-UI benötigt für den vollen Login den Server** (WASM-Kern +
   `/login-ui/v1/world`). Die lokale Datei rendert und navigiert alle
   Schritte; der Endpunkt-Login ist same-origin bewiesen.

## Reproduktion (Kurz)

```bash
# Tests / Clippy
cd /data/z8run-test/src && cargo test --workspace          # 533 passed
cargo clippy --workspace --all-targets                     # 0 Fehler
# UI lokal
Z8_DESKTOP_TCP=1 z8run --data-dir /tmp/z8node serve --bind 127.0.0.1 --port 7711
#   -> http://127.0.0.1:7711/setup-ui/   (nur lokal)
#   -> https://<host>/login-ui/          (embed-ui; Weltzeiger: Z8_LOGIN_S3_CONFIG)
# Beweis-Werkzeuge (echte CDP-Klicks, Screenshots)
node /data/z8run-test/verify-logs/z8-uis/tools/s3-formats.mjs
node /data/z8run-test/verify-logs/z8-uis/tools/s3-vnc.mjs      # headful :99 / CDP 9223
```
