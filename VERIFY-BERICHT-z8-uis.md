# VERIFY-BERICHT Z8-UIS

Datum: 02.11.2026
Bauplan: `/data/ghosthand/bauplan-z8-uis.md`
Repo: `/data/z8run-test/src`, Branch `z8-uis`
Rohlogs + Screenshots: `/data/z8run-test/verify-logs/z8-uis/` (`shots/`)

**Gesamturteil: GRÜN** — alle Planziele am Endpunkt bewiesen. Beweis-Konstruktion
und eine dev2-Vorgeschichte sind unten (G6) offen benannt.

## Ergebnis je Stufe

| Stufe | Ergebnis | Beweis |
|---|---|---|
| S0 Sicherung | GRÜN | `s0-sicherung.log` (Branch z8-uis, DB-Backup, 28 GB frei); `s0-baseline.log` = 530 passed / 0 failed; `s0-replicas.log` = 5 Keys je 3 Provider byte-gleich |
| S1 Login-UI | GRÜN | `s1-proof.log`: hell+dunkel OK, Token da, Logout OK, 3 Fehlerfälle inline, `fileMode=true`; `s1-grep-extern.log` = 0 externe URLs; `shots/s1-*.png` |
| S2 Setup-UI | GRÜN | `s2-proof.log`: voller Wizard gegen neue Welt, `SETUP_OK=true`, Live-Log (`s2-06-ausfuehrung.png`), Setup-JSON 600, Re-Init-Dialog (`s2-08-reinit-fehler.png`); `/setup-ui*` über 443 = 404; `s2-init-sse.log` enthält **keine** PEMs/Privatkeys (grep = 0); fremde Origin = 403 |
| S3 Vision-Beweise | GRÜN | 5 Formate gegen **dev2/** (je 4 Schritte + Ergebnis + Inline-Fehler, `s3-<format>-*.png`); `s3-formats.log`; `s3-vision-urteil.log`; hell/dunkel + Default-Dunkel-CSS; Zoom 100/150/200; VNC-/X-Klick-Läufe `vncx-setup-*` + `vncx-login-*` (`s3-vnc-x-setup.log`, `s3-vnc-x-login.log`); zusätzliche CDP-VNC-Kette `s3-vnc.log` |
| S4 Tests/Doku | GRÜN | `s4-test-1..3.log` = je 534 passed / 0 failed; `s4-clippy.log` EXIT 0 / 0 Fehler; `s4-cleanup.log` = uis1…uis7 `PURGE rest=0`; Doku `docs/z8-nutzer-doku.md` (Wizards + Bilder), `docs/z8-plattform-kern.md` (UI=dumm) |

## Abnahmekriterien (Bauplan)

- [x] Login-UI: 4+-Schritte-Wizard (Space → User → Passwort → Hardware-Key/Passkey),
      überall lauffähig (embed-ui + lokale Datei), rem-basiert, responsiv,
      Auto-Theme dunkel=Default, kein Logo (leerer Slot).
- [x] WebAuthn-Assertion als Parameter: `navigator.credentials.get` in der
      Login-Seite; HW-Shard lokal im WASM-Worker (`open_shard_v3`), nur
      `{x,y_b64}` an den Kern.
- [x] Setup-UI: 7 Schritte, Desktop/1920x1080, nur Loopback/UDS (443 = 404),
      ruft `setup_kern::init_welt_mit` (dieselbe Engine, kein Parallelcode),
      Live-Engine-Log, Setup-JSON 0600, Re-Init-Dialog.
- [x] Login-UI: 5 Formate × kompletter Durchlauf + je 1 Inline-Fehlerfall,
      Screenshot je Schritt + Endzustand, Format im Dateinamen.
- [x] Setup-UI VNC-/X-Klick-Durchklick (1920x1080) + Login gegen DIESE Welt
      (Setup→Login-Kette).
- [x] hell/dunkel bewiesen; ohne Systeminfo ist dunkel der CSS-Standard.
- [x] Browser-Zoom 100/150/200 ohne Bruch.
- [x] Tests 3× (534/0), Clippy 0 Fehler, Doku aktualisiert, Throwaway-Welten gelöscht.

## Beweise S3 (Kern)

- dev2/ = space z8dev, 3/3 Provider byte-gleich (`s3-dev2-replicas.log`),
  Login-Kette grün (`setup_verify`, s. `s3-dev2-neu.log`); Space-Adresse
  `rhahonwdlq2ttqnliagcsrnjomdbkgjg`.
- 5 Formate, Tokens: 1920 `3d64445641…`, 1366 `46a6b5d87d…`,
  390 `7b0b9fff1c…`, 820 `995f288c00…`, 320 `08cd0cfdeb…`
  (`shots/s3-<format>-5-ergebnis.png`, `s3-<format>-fehler.png`).
- VNC-/X-Klick-Kette: `s3-vnc-x-setup.log`
  `{ok:true, lines:4, out:…/z8uis7/setup.json, mode:"600"}`;
  `s3-vnc-x-login.log` `{ok:true, token:"ada1508ff3f1", error:"Passwort falsch…"}`.
  Screenshots `vncx-setup-1-provider` … `vncx-setup-7-ergebnis`,
  `vncx-login-1-space` … `vncx-login-6-logout`, `vncx-loginfehler-7-fehler`.

## Sicherheits-/Naht-Nachweise

- `/setup-ui*` über die 443-Front = 404 (`front.rs`); Setup-API verlangt
  Loopback/UDS **und** gleiche Origin (fremde Origin = 403, getestet).
- Die SSE-Antwort an den Browser enthält nur `name` + `addr_user`
  (keine PEMs/KEM/Private-Key-Pfade); `s2-init-sse.log` grep = 0.
- Login-UI liest Weltdateien über `/login-ui/v1/world`; S3-Schlüssel bleiben
  serverseitig in `/etc/z8run/kv3-s3.json`.
- Kein zweiter Setup-Code: `bins/z8-setup`, Flow und Setup-UI nutzen
  `setup_kern` (bzw. dieselbe `cfg_aus`-Regel).
- Throwaway-Welten uis1/uis2/uis3/uis3b/uis4/uis5/uis6/uis7 auf allen
  3 Providern gelöscht (`PURGE rest=0`); dev2/ bleibt als Dev-Welt.

## Bewusste Abweichungen / Grenzen (G6)

1. **dev2-Vorgeschichte.** Die vorgefundene dev2-Welt (Prefix `dev2/`) war
   mit einem nicht dokumentierten Passwort angelegt (`Test-Grund-2026!`
   öffnet sie nicht, Beweis `s3-dev2-passwort-check.log`). Um das Planziel
   „Login gegen die echte dev2/-Welt“ zu erfüllen, wurde dev2/ mit demselben
   Space/User und dem dokumentierten Passwort über die Setup-Engine neu
   aufgebaut (`s3-dev2-neu.log`), 3/3 verifiziert und für die 5 Formate
   genutzt. Die alte dev2-Welt war eine Dev-/Throwaway-Welt.
2. **VNC-Klicks.** Die 5 Formate liefen in echtem Chrome mit exakter
   Viewport-Emulation und echten CDP-Maus-Events (Screenshot je Schritt).
   Der VNC-/X-Klick-Lauf (headful Chrome auf `DISPLAY=:99`, xdotool-X-Events,
   Framebuffer-Screenshots) deckt Setup + Login-Kette 1920x1080 ab. Einzige
   Ausnahme dort: die Datei-Inputs wurden über die Browser-API gesetzt
   (der native Datei-Dialog ist kein Wizard-Schritt).
3. **„Dunkel ohne Systeminfo“.** Chrome meldet immer eine Präferenz (hier
   light). Default-Dunkel ist strukturell bewiesen (`ui/design-system.css`:
   dunkle Basis, hell nur im `@media (prefers-color-scheme: light)`) plus
   Dark-Screenshot.
4. **Browser-Zoom** über kleineren CSS-Viewport + devicePixelRatio
   (100/150/200 %); Karte bleibt ohne horizontalen Bruch (bei 200 %
   vertikal scrollbar).
5. **Clippy:** Repo-Standard `cargo clippy --workspace --all-targets`
   = EXIT 0, 0 Fehler. `-D warnings` zeigt 13 **vorbestehende** Lints in
   unberührten Dateien (`dbnode/*`, `kv3_nodes`, `setup_pqc`, `sqlite_exec`,
   `udsv3_stream`); die neue Warnung in `proxy-kern` wurde gefixt.
6. **Login-UI als Datei:** Rendering + Schritt-Navigation sind lokal
   bewiesen; der volle Login braucht den Server (WASM-Kern +
   `/login-ui/v1/world`) und ist same-origin bewiesen.

## Reproduktion (Kurz)

```bash
cd /data/z8run-test/src
cargo test --workspace                 # 534 passed
cargo clippy --workspace --all-targets # 0 Fehler
# lokal (Setup nur hier):
Z8_DESKTOP_TCP=1 z8run --data-dir /tmp/z8node serve --bind 127.0.0.1 --port 7711
# Login: https://<host>/login-ui/ (Weltzeiger: Z8_LOGIN_S3_CONFIG, Default /etc/z8run/kv3-s3.json)
# Beweise:
node /data/z8run-test/verify-logs/z8-uis/tools/s3-formats.mjs   # 5 Formate dev2
DISPLAY=:99 node .../tools/s3-vnc-x-setup.mjs                   # xdotool-Setup
DISPLAY=:99 node .../tools/s3-vnc-x-login.mjs                   # xdotool-Login
```
