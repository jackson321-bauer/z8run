#!/usr/bin/env python3
"""S3: Export-Binary-Beweis (cli+server) MIT GESTOPPTEM z8run.

Baut eine frische Test-Welt + Credential über die exportierten Setup-Server,
ruft /challenge über die Server-Binary ab und führt den Login über die
CLI-Binary aus (stdin). Prüft Assertion-Fall, Replay-401, keyless-401 und
die unix-out-Übergabe an den Proxy-Socket (Session inkl. Masterkey-Feld).
"""

from __future__ import annotations

import json
import os
import subprocess
import time

import z8_webauthn_login_e2e as e2e

LOG = e2e.LOG
BIN_CLI = f"{e2e.EXPORTS}/bin/z8_KV3_Login_WebAuthn_cli"
BIN_SERVER = f"{e2e.EXPORTS}/bin/z8_KV3_Login_WebAuthn_server"
CLI_PROJECT = f"{e2e.EXPORTS}/z8wa-login-cli"


def log(name: str, obj) -> None:
    with open(f"{LOG}/s3-{name}.json", "w") as f:
        json.dump(obj, f, indent=2)


def run_cli(body: dict):
    # CLI erwartet den Trigger-BODY (nicht das Hook-Envelope).
    t0 = time.time()
    p = subprocess.run([BIN_CLI], input=json.dumps(body).encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    dur = round(time.time() - t0, 3)
    out = p.stdout.decode(errors="replace").strip()
    try:
        parsed = json.loads(out) if out else {}
    except Exception:
        parsed = {"raw": out}
    return p.returncode, parsed, p.stderr.decode(errors="replace"), dur


def main():
    rc_z8 = subprocess.run(["systemctl", "stop", "z8run"], capture_output=True, text=True)
    print(f"[S3] z8run gestoppt rc={rc_z8.returncode}")

    e2e.os.makedirs(e2e.KEYS, exist_ok=True)
    e2e.shutil.rmtree(e2e.KEYS, ignore_errors=True)
    e2e.os.makedirs(e2e.KEYS)
    password = "pw-" + os.urandom(8).hex()
    print(f"[S3] Prefix leeren: {e2e.wipe_prefix()} Objekte")

    e2e.start(e2e.BIN_SETUP, e2e.SOCK_SETUP, "s3-setup")
    e2e.start(e2e.BIN_WA, e2e.SOCK_WA, "s3-webauthn")
    e2e.start(BIN_SERVER, e2e.SOCK_LOGIN, "s3-login-server")
    proxy = e2e.start_proxy()
    try:
        st, resp = e2e.unix_post(e2e.SOCK_SETUP, "/setup", {
            "space": e2e.SPACE, "s3": {"prefix": e2e.PREFIX},
            "users": [{"name": "anna", "password": password, "engines": ["demo"]}],
            "quorum": {"n": 3, "threshold": 2},
        })
        assert st == 200 and resp.get("ok"), (st, resp)
        user = resp["users"][0]
        expected = user["user_master_sha256"]
        key, pem_path, kem, cred_id, _ = e2e.register("anna", with_pqc=True)
        shard = json.loads(subprocess.check_output([
            e2e.SG, "shard-open", "--s3-config", e2e.S3, "--prefix", e2e.PREFIX,
            "--addr", user["addr_user"], "--key", pem_path, "--kem", kem,
        ]).decode())

        unix = {"space": e2e.SPACE, "user": "anna", "password": password}
        st, ch = e2e.unix_post(e2e.SOCK_LOGIN, "/challenge", {"user": "anna"})
        assert st == 200, (st, ch)
        body = {**unix, **e2e.assertion(key, cred_id, ch["webauthn_challenge"], 2),
                "shamir_hw": shard["shamir_hw"], "s3": {"prefix": e2e.PREFIX}}
        rc, out, err, dur = run_cli(body)
        assert rc == 0, (rc, out, err)
        assert out.get("master_sha256") == expected, (out.get("master_sha256"), expected)
        assert e2e._proxy_body.get("session", {}).get("master_sha256") == expected
        log("cli-ok", {"exit": rc, "seconds": dur, "master_sha256": out["master_sha256"],
                       "session_view": out.get("session_view"),
                       "proxy_fields": sorted(e2e._proxy_body["session"].keys())})
        print(f"[S3] CLI ASSERTION OK exit={rc} master={out['master_sha256'][:16]}")

        # Replay: neue Challenge, gleicher Counter
        st, ch = e2e.unix_post(e2e.SOCK_LOGIN, "/challenge", {"user": "anna"})
        body = {**unix, **e2e.assertion(key, cred_id, ch["webauthn_challenge"], 2),
                "shamir_hw": shard["shamir_hw"], "s3": {"prefix": e2e.PREFIX}}
        rc, out, err, dur = run_cli(body)
        assert rc == 1, (rc, out, err)
        log("cli-replay", {"exit": rc, "error": out.get("error")})
        print(f"[S3] CLI REPLAY -> exit={rc}: {out.get('error')}")

        # keyless: keine Assertion
        st, ch = e2e.unix_post(e2e.SOCK_LOGIN, "/challenge", {"user": "anna"})
        body = {**unix, "shamir_hw": shard["shamir_hw"], "s3": {"prefix": e2e.PREFIX}}
        rc, out, err, dur = run_cli(body)
        assert rc == 1, (rc, out, err)
        log("cli-keyless", {"exit": rc, "error": out.get("error")})
        print(f"[S3] CLI KEYLESS -> exit={rc}: {out.get('error')}")

        # Export-Projekt: path-Dependency + kein nachgebauter Node-Code
        tree = subprocess.check_output(
            ["cargo", "tree", "--offline"], cwd=CLI_PROJECT,
            env=dict(os.environ, PATH=os.path.expanduser("~/.cargo/bin") + ":" + os.environ["PATH"]),
        ).decode()
        assert "z8run-core" in tree and "/data/z8run-test/src/crates/z8run-core" in tree, tree[:500]
        grep = subprocess.run(
            ["grep", "-R", "fn process", f"{CLI_PROJECT}/src"],
            capture_output=True, text=True,
        )
        assert grep.returncode == 1 and grep.stdout.strip() == "", grep.stdout
        log("cli-tree", {
            "path_dep": [l.strip() for l in tree.splitlines() if "z8run-core" in l][:2],
            "fn_process_treffer": 0,
        })
        print("[S3] cargo tree path-dep OK, grep 'fn process' = 0")
        print("== S3 GRUEN ==")
    finally:
        proxy.shutdown()
        for p in e2e._procs:
            p.terminate()
        for p in e2e._procs:
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()
        subprocess.run(["systemctl", "start", "z8run"], capture_output=True, text=True)
        print("[S3] z8run wieder gestartet")


if __name__ == "__main__":
    main()
