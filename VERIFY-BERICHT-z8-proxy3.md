# VERIFY-BERICHT Z8-PROXY3 — Stand 01.11.2026

Repo: `/data/z8run-test/src`, Branch `z8-proxy3`, Code-HEAD `494a6df` (letzter getesteter Stand).
Bauplan: `/data/ghosthand/bauplan-z8-proxy3.md`.
Rohlogs: `/data/z8run-test/verify-logs/z8-proxy3/`.

**Gesamturteil: TEILGRÜN.** S1/S2/S3-Kern/S5/S6-Install sind bewiesen.
S4 ist in den im Plan geforderten Punkten (Proxy-Kern/dbnode im Worker,
wasmi-Apps, Browser-Passbox-Login, S3-Fetch-E2E) NICHT fertig; S3-OPFS
ist Persistenzschicht statt VFS. Diese Abgrenzungen sind unten
ausdrücklich benannt (G6) — keine stille Ausnahme.

## Ergebnis je Stufe

| Stufe | Ergebnis | Beweis |
|---|---|---|
| S0 Sicherung/Backup | GRÜN | `s0-sicherung.log`; Branch/Backup, >50 GB frei |
| S0 Baseline 516×3 | GRÜN | `s0-baseline-1/2/3.log` = je **516 passed / 0 failed**; `s0-baseline-rc.log` = rc 0/0/0 |
| S1 Port-Kill | GRÜN | `s1-ss-vorher.log` (7700/7710/7800/443) vs. `s1-ss-nachher.log`/`s1-port-kill-grep.log` (nur 443); grep Bind = 0 Treffer |
| S1 udsv3 | GRÜN | `s1-udsv3-e2e.log` (Chiffre, Replay inkl. neuer Verbindung, Downgrade strikt/debug); `s1-udsv3-live.log` (voller Login-Frame, Login→Proxy→DB live, Token redigiert) |
| S2 RAM | GRÜN | `s2-ram-vmlck.log`: z8run 80 kB, kv-proxy 84 kB, kv-login 68 kB (Arena+Session-mlock); `ram::tests` (mlock+zeroize), `KeyEnvelope`/Session-mlock+zeroize, udsv3-Master zeroize |
| S3 SQLCipher raus | GRÜN | Cargo: `rusqlite/libsqlite3-sys` nur `bundled`; `grep sqlcipher` in Cargo.lock = 0; Z8FC1-Dateien live (`s3-live-cipher-files.log`: `5a38464331`) |
| S3 vec-WASM | GRÜN | `s3-wasm-vec-node.log`: `WASM_VEC_VERSION=v0.1.9`; Chrome-Selftest `s3-wasm-selftest.log` |
| S3 OPFS | GRÜN (Persistenz) / GELB (VFS) | OPFS write/read/list/delete/persist/quota im Chrome-Test; **kein OpfsBackend am StorageBackend-Trait, kein OPFS-VFS** (Abgrenzung 1) |
| S3 WASM/nativ-Form | GRÜN | `dbnode_wasm_compat` mit committeten Fixtures in BEIDE Richtungen (WASM→nativ, nativ→WASM), kein Skip |
| S4 AutoLock/Offline/Konflikt | GRÜN (Teil) | `s3-wasm-selftest.log` (AutoLock 1 s, S3 fail-closed, ReplayRemote/ChainMismatch-Event); installiertes /wasm enthält ReplayRemote (nach Rebuild) |
| S4 Kern/Apps/Login | ROT | Proxy-Kern+dbnode nicht im Worker, keine wasmi-Apps, kein Passbox/S3-Login (Abgrenzungen 2–4) |
| S5 Exporter native | GRÜN | `s5-native-export.log` (Linux gebaut, Win/mac `build_bar:true`), `s5-native-run.log` |
| S5 Exporter browser | GRÜN | `s5-browser-bundle.log`; `s5-browser-443.log` (`FASSADE={"status":200,...}`, Worker über 443) |
| S5 CORS | GRÜN mit Blocker | `s5-cors-set.log`: GET fremde Origin 200, PUT fremde Origin 403, PUT eigene Origin 200; One-Bucket-Wildcard-GET = dokumentierter Blocker |
| S6 Installation | GRÜN | `s6-install-proof.log`: nur 443, `/` `/wasm/` `/proxy` `/login` = 200, PQC `X25519MLKEM768` true, Legacy X25519 |
| S6 Tests | GRÜN | `final3-test-1/2/3.log`: je **533 passed / 0 failed**, 100 s Pause (HEAD 494a6df) |
| S6 Doku | GRÜN | `docs/z8-proxy3.md` (Port-Map, udsv3, RAM, Z8FC1, Browser, AutoLock/Offline/Konflikt, Exporter, CORS, WAMR/iOS/Mobile, Abgrenzungen) |
| S6 Zero-Kontext-Audit | GRÜN (durchgeführt) | Externer Audit hat GELB/ROT gefunden; Fixes: Replay cross-connection+Random-Nonce, Engine-UDS udsv3, kv_auth-UDS, kv-login mlock/zeroize, Fixtures beidseitig, persist/quota-Asserts, Konflikt-Event. Restliche Abgrenzungen bleiben deklariert. |

## Harte Beweise (Auszug)

```
ss -tlnp | grep -E ':7700|:7710|:7800|:443'
→ nur 0.0.0.0:443 (z8run)

curl / /wasm/index.html /proxy/v1/status /login/v1/health → 200/200/200/200
z8-tls-proof → GRUPPE X25519MLKEM768 PQC true (legacy X25519 false)
/proc/<pid>/status → VmLck 100/80 kB
Z8FC1 live → 5a38464331 (demo/meta-cluster/otel)
WASM_VEC_VERSION=v0.1.9
WASM_NATIVE_COMPAT_OK / NATIVE_TO_WASM_OK
FASSADE={"body":{"kern":"z8run-browser","sqlite":"wasm","worker":true},"status":200}
cargo test --workspace → 532 passed ×3
```

## Bewusste Abgrenzungen (G6)

1. **OPFS ist Persistenzschicht, kein SQLite-VFS.** SQLite läuft im
   Worker-RAM; nach Sync wird die DB als Z8FC1 über SyncAccessHandle
   nach OPFS geschrieben. Es gibt kein `OpfsBackend` am nativen
   `StorageBackend`-Trait. Die SyncAccessHandle-/Chiffre-/Replay-/
   Konflikt-Semantik ist vorhanden, der VFS-Punkt des Plans nicht 1:1.
2. **Der native Proxy-Kern+dbnode läuft nicht im WASM-Worker.** Im
   Browser liegen SQLite+vec, File-Cipher, OPFS, S3/SigV4, Session,
   AutoLock/Offline und die postMessage-Fassade; der DbNode bleibt
   nativ.
3. **wasmi-Apps fehlen** komplett (keine wasmi-Dependency). WAMR ist als
   Ausweichpfad dokumentiert, aber nicht gebaut.
4. **Browser-Login (Passbox → S3-Hashdatei → Master) fehlt.** Die
   Fassade nimmt `master_b64` direkt; der echte Browser-Login gegen die
   dev-Welt ist nicht als E2E gelaufen.
5. **S3 im Browser:** SigV4 ist mit dem AWS-Testvektor bewiesen und
   `fetch`-Glue vorhanden; ein echter PUT/GET-Roundtrip gegen den
   DD-Testprefix ist mangels Browser-Credentials/UI nicht gelaufen.
6. **CORS-One-Bucket:** S3-CORS kann nicht nach Prefix trennen; die
   GET-Wildcard gilt für den ganzen Bucket (auch session/WAL-GET).
   Sauberer Hausmeister-Weg = eigener b2b-Bucket (nicht umgesetzt).
7. **Win/mac build-bar** ist `rustc --target --emit=metadata` (Std für
   Target vorhanden), kein vollständiger App-Cross-Link; echte
   Binaries/Testgeräte fehlen.
8. **Desktop-Loopback-TCP**: nur Desktop-Modus (`Z8_DESKTOP_TCP=1`)
   öffnet Loopback für den Browser; `serve`/Produktion nur 443+UDS.
9. **Alte dev-Welten** wurden einmal umbenannt (`*.alt-<ts>`) und werden
   beim nächsten Login/Setup neu als Z8FC1 angelegt.
10. **Engine-UDS (`z8run.sock`)** spricht jetzt udsv3 (Kontext `engine`);
    `unix-out` und die MCP-Setup/Login-Tools wurden angepasst, rohe
    `curl --unix-socket`-Beispiele aus alten Docs nicht.

## Testzahlen

- Baseline (`78f04ce`): **516 passed** (Lauf 1; weitere Läufe im Log).
- Neuer Stand: **533 passed ×3** (100 s Pause), 0 failed (HEAD 494a6df, `final3-test-*.log`).
- `cargo clippy --workspace --all-targets`: rc=0 (Warnungen, keine Fehler).
- Neue Tests u. a.: udsv3 (Chiffre/Replay/Downgrade/Cross-Replay),
  RAM/mlock/zeroize, Z8FC1-Datei+VFS, WASM/nativ-Fixtures, SigV4,
  AutoLock/Offline/Konflikt, Browser-Selftest.
