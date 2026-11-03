#!/usr/bin/env python3
"""Z8-Setup als SecretManager — E2E-Beweis (S0/S2/S3).

Phasen:
  prepare  Flow-JSONs aus der DB erzeugen + Export-Projekte bauen
  world    frische Test-Welt (workspace-Cluster, demo.db, config/meta.db)
  secrets  5 Auftragsarten + Negativ 403 + Live-Reader (S3, read-only)
  s3proof  s3-list: secret.db im eigenen Cluster-Praefix

Keine Secrets im Log: Werte werden nur als SHA-256 gedruckt.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SRC = "/data/z8run-test/src"
D = "/data/z8run-test/verify-logs/z8-setup-secretmanager"
DB = "/data/z8run/data/z8run.db"
S3 = "/etc/z8run/kv3-s3.json"
PREFIX = os.environ.get("SM_PREFIX", "z8sm/run1/")
SPACE = os.environ.get("SM_SPACE", "sm1")
USERS = [("anna", "anna-pass-123"), ("bernd", "bernd-pass-123")]
TOOLS = f"{SRC}/target/release"
EXP = f"{D}/exports"
SOCK_DIR = f"{D}/socks"
FLOW_IDS = {
    "Z8-Setup": "01a18762-179c-719c-9bb8-6ea8fb247e72",
    "Z8-Setup-Operation": "01a18762-17d3-74b9-b2a5-dcec885872f8",
}
OPS = [
    ("secret-anlegen", "secret-anlegen"),
    ("secret-setzen", "secret-setzen"),
    ("secret-rotieren", "secret-rotieren"),
    ("secret-revozieren", "secret-revozieren"),
    ("secret-liste", "secret-liste"),
]


def out(*a):
    print(*a, flush=True)


def los():
    for p in (D, EXP, SOCK_DIR, f"{D}/flows", f"{D}/keys"):
        os.makedirs(p, exist_ok=True)


def flow_data(name: str) -> dict:
    c = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    row = c.execute("select data from flows where id=?", (FLOW_IDS[name],)).fetchone()
    c.close()
    return json.loads(row[0])


def node(nid, typ, label, cfg, error=True, trigger=False, outnode=False):
    d = {"type": typ, "label": label, "config": cfg}
    if trigger:
        d["inputs"] = []
        d["outputs"] = [{"id": "output", "name": "Output", "type": "object"}]
    elif outnode:
        d["inputs"] = [{"id": "input", "name": "Input", "type": "any"}]
        d["outputs"] = []
    else:
        d["inputs"] = [{"id": "input", "name": "Input", "type": "any"}]
        d["outputs"] = ([{"id": "output", "name": "Output", "type": "object"},
                         {"id": "error", "name": "Error", "type": "any"}]
                        if error else [{"id": "output", "name": "Output", "type": "object"}])
    return {"id": nid, "type": "z8node", "position": {"x": 0, "y": 0}, "data": d}


def edge(src, dst, port="output"):
    return {"id": f"e-{src}-{port}-{dst}", "source": src, "sourceHandle": port,
            "target": dst, "targetHandle": "input"}


def erweitere_operation(flow: dict) -> dict:
    pos = flow["metadata"]["positions"]
    nodes = pos["canvas_nodes"]
    edges = pos["canvas_edges"]
    for path, typ in OPS:
        p = path.replace("secret-", "")
        nodes += [
            node(f"in-{p}", "unix-in", f"POST /{path}", {"method": "POST", "path": f"/{path}"}, trigger=True),
            node(f"auth-{p}", "setup-auth", f"Setup-Key-Auth ({typ})", {
                "s3Config": S3, "registryKey": "setup/registry.txt",
                "shardsKey": "setup/setup-shards.txt", "op": typ}),
            node(f"op-{p}", typ, f"SecretManager {typ}", {"s3Config": S3, "registryKey": "setup/registry.txt"}),
            node(f"res-{p}", "setup-result", f"Ergebnis {typ}", {}, error=False),
            node(f"out-{p}", "http-out", f"200 {typ}", {"statusCode": 200}, outnode=True),
            node(f"aerr-{p}", "http-out", f"403 {typ}", {"statusCode": 403}, outnode=True),
            node(f"rerr-{p}", "http-out", f"400 {typ}", {"statusCode": 400}, outnode=True),
        ]
        edges += [
            edge(f"in-{p}", f"auth-{p}"), edge(f"auth-{p}", f"op-{p}"),
            edge(f"op-{p}", f"res-{p}"), edge(f"res-{p}", f"out-{p}"),
            edge(f"auth-{p}", f"aerr-{p}", "error"), edge(f"op-{p}", f"rerr-{p}", "error"),
        ]
    # Bestehende Auftragsart s3-list (read-only) für den S3-Beweis.
    nodes += [
        node("in-s3l", "unix-in", "POST /s3-list", {"method": "POST", "path": "/s3-list"}, trigger=True),
        node("op-s3l", "s3-list", "S3 auflisten", {"s3Config": S3}),
        node("res-s3l", "setup-result", "Ergebnis s3-list", {}, error=False),
        node("out-s3l", "http-out", "200 s3-list", {"statusCode": 200}, outnode=True),
        node("rerr-s3l", "http-out", "400 s3-list", {"statusCode": 400}, outnode=True),
    ]
    edges += [edge("in-s3l", "op-s3l"), edge("op-s3l", "res-s3l"),
              edge("res-s3l", "out-s3l"), edge("op-s3l", "rerr-s3l", "error")]
    return flow


def phase_prepare():
    los()
    initial = flow_data("Z8-Setup")
    operation = erweitere_operation(flow_data("Z8-Setup-Operation"))
    json.dump(initial, open(f"{D}/flows/initial.json", "w"), indent=1)
    json.dump(operation, open(f"{D}/flows/operation.json", "w"), indent=1)
    out(f"[prepare] Flow-JSONs: initial={len(initial['metadata']['positions']['canvas_nodes'])} "
        f"operation={len(operation['metadata']['positions']['canvas_nodes'])} Knoten")
    env = dict(os.environ)
    env["CARGO"] = "/root/.cargo/bin/cargo"
    env["CARGO_TARGET_DIR"] = f"{EXP}/target"
    for name, f in (("initial", "initial"), ("operation", "operation")):
        d = f"{EXP}/{name}"
        cmd = [f"{TOOLS}/z8-export", "--flow-file", f"{D}/flows/{f}.json",
               "--out", d, "--mode", "server", "--build"]
        r = subprocess.run(cmd, env=env, capture_output=True, text=True)
        log = f"{D}/s0/export-{name}.log"
        open(log, "w").write(" ".join(cmd) + "\n" + r.stdout + r.stderr)
        if r.returncode != 0:
            raise SystemExit(f"export {name} fehlgeschlagen: siehe {log}")
        tdir = f"{EXP}/target/release"
        cargo = open(f"{d}/Cargo.toml").read()
        binname = [l.split("=")[1].strip().strip('"') for l in cargo.splitlines()
                   if l.strip().startswith("name =")][-1]
        assert os.access(f"{tdir}/{binname}", os.X_OK), binname
        out(f"[prepare] {name}: {binname}")
        open(f"{D}/{name}.bin", "w").write(f"{tdir}/{binname}")


def start(binary: str, sock: str) -> subprocess.Popen:
    if os.path.exists(sock):
        os.unlink(sock)
    env = dict(os.environ, Z8_EXPORT_SOCK=sock)
    p = subprocess.Popen([binary], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(200):
        if os.path.exists(sock):
            return p
        if p.poll() is not None:
            raise SystemExit(f"Server startete nicht: {p.stdout.read().decode()}")
        time.sleep(0.05)
    raise SystemExit("Socket nicht erschienen")


def post(sock: str, path: str, body: dict, timeout=300) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(sock)
    s.sendall((f"POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
               f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data)
    raw = b""
    while True:
        c = s.recv(65536)
        if not c:
            break
        raw += c
    s.close()
    head, _, rest = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1]) if head else 0
    try:
        return status, json.loads(rest or b"{}")
    except Exception:
        return status, {"raw": rest.decode(errors="replace")}


def auth(paths: dict, op: str, space: str) -> dict:
    a = open(paths["p1"]).read()
    b = open(paths["p2"]).read()
    signed = f"{op}:{space}:{os.urandom(8).hex()}"
    key = serialization.load_pem_private_key(a.encode(), password=None)
    sig = key.sign(signed.encode(), ec.ECDSA(hashes.SHA256()))
    ml = subprocess.check_output([f"{TOOLS}/z8-stahlgitter", "mldsa-sign",
                                  "--key", paths["ml"], "--msg", signed]).decode().strip()
    return {"setup_pems": [a, b],
            "setup_pqc_keys": [paths["kem1"], paths["kem2"]],
            "setup_signed": signed,
            "setup_signature": base64.b64encode(sig).decode(),
            "setup_mldsa_signature": ml}


def keypaths(resp: dict) -> dict:
    ps = resp["setup_pems"]
    p1 = f"{D}/keys/setup-hw1.pem"
    p2 = f"{D}/keys/setup-hw2.pem"
    open(p1, "w").write(ps[0]["pem"])
    open(p2, "w").write(ps[1]["pem"])
    os.chmod(p1, 0o600)
    os.chmod(p2, 0o600)
    return {"p1": p1, "p2": p2, "kem1": ps[0]["pqc_dk_path"],
            "kem2": ps[1]["pqc_dk_path"], "ml": ps[0]["mldsa_sk_path"]}


def phase_world():
    los()
    binary = open(f"{D}/initial.bin").read().strip()
    sock = f"{SOCK_DIR}/initial.sock"
    p = start(binary, sock)
    log = open(f"{D}/s0/world-server.log", "w")
    body = {"space": SPACE, "setupKeys": 3, "hwKeys": 2,
            "s3": {"prefix": PREFIX},
            "users": [{"name": n, "password": pw, "engines": ["demo", "fts5"]} for n, pw in USERS]}
    try:
        st, resp = post(sock, "/setup", body)
    finally:
        p.terminate()
        log.write(p.stdout.read().decode(errors="replace"))
        log.close()
    if st != 200 or not resp.get("ok"):
        raise SystemExit(f"Weltbau ROT: HTTP {st} {str(resp)[:400]}")
    json.dump(resp, open(f"{D}/world-response.json", "w"), indent=1)
    open(f"{D}/spec.json", "w").write(json.dumps(
        {"space": SPACE, "users": [{"name": n, "password": pw} for n, pw in USERS]}))
    kp = keypaths(resp)
    json.dump(kp, open(f"{D}/keys/paths.json", "w"))
    out(f"[world] GRUEN space={resp['space']} addr_space={resp['addr_space']} "
        f"users={len(resp['users'])} files={len(resp['files'])}")


def hashfile_pfad():
    return f"{D}/hashfiles"


def download_hashfiles():
    """Lädt b2b/{addr}.txt via einen Mini-Aufruf des operation-Binaries? Nein:
    die User-Hashdatei wird aus der Welt-Antwort/S3 über den Reader geholt.
    Hier nur Verzeichnis anlegen; der Reader holt sie selbst aus S3."""
    os.makedirs(hashfile_pfad(), exist_ok=True)


def run_reader(resp: dict, name: str, pw: str, label: str, expect: str | None = None) -> dict:
    env = dict(os.environ, SECRET_S3_CONFIG=S3, SECRET_PREFIX=PREFIX,
               SECRET_SPACE=SPACE, SECRET_USER_NAME=name, SECRET_USER_PW=pw,
               SECRET_OUT=f"{D}/reader-tmp")
    if expect:
        env["SECRET_EXPECT"] = expect
    r = subprocess.run([f"{TOOLS}/examples/secret_reader"], env=env, capture_output=True, text=True)
    line = (r.stdout + r.stderr).strip()
    open(f"{D}/s3/reader-{label}.log", "w").write(line + f"\nEXIT={r.returncode}\n")
    if r.returncode != 0:
        raise SystemExit(f"Reader {label} ROT:\n{line}")
    out(f"[reader:{label}] " + line.replace("\n", " | "))
    return {"raw": line}


def phase_secrets():
    los()
    os.makedirs(f"{D}/s3", exist_ok=True)
    resp = json.load(open(f"{D}/world-response.json"))
    space = resp["space"]
    kp = json.load(open(f"{D}/keys/paths.json"))
    binary = open(f"{D}/operation.bin").read().strip()
    sock = f"{SOCK_DIR}/operation.sock"
    os.makedirs(f"{D}/s2", exist_ok=True)
    os.makedirs(f"{D}/s3", exist_ok=True)
    p = start(binary, sock)
    srvlog = open(f"{D}/s2/server-operation.log", "w")
    try:
        # NEGATIV: alle 5 ohne Setup-Key -> 403
        for path, _ in OPS:
            st, body = post(sock, f"/{path}", {"s3": {"prefix": PREFIX}, "user": "anna",
                                               "ns": "demo", "name": "x", "wert": "x"})
            assert st == 403, (path, st, body)
            out(f"[NEG] /{path} ohne Setup-Key -> HTTP {st}")

        # 1) secret-anlegen (N Userspaces in EINEM Hook-Aufruf)
        body = {"s3": {"prefix": PREFIX}, "users": [n for n, _ in USERS],
                "userPasswords": {n: pw for n, pw in USERS}, **auth(kp, "secret-anlegen", space)}
        st, o = post(sock, "/secret-anlegen", body)
        assert st == 200 and o.get("secrets_anlegen", {}).get("ok"), (st, o)
        clusters = o["secrets_anlegen"]["clusters"]
        assert len(clusters) == 2, clusters
        json.dump(clusters, open(f"{D}/s2/clusters.json", "w"), indent=1)
        out(f"[1] ANLEGEN OK clusters={len(clusters)} "
            + ", ".join(f"{c['user']}:{c['cluster_id'][:8]}@{c['prefix']}" for c in clusters))

        wert1 = "sm-test-secret-v1-" + os.urandom(4).hex()
        wert2 = "sm-test-secret-v2-" + os.urandom(4).hex()
        sha1 = __import__("hashlib").sha256(wert1.encode()).hexdigest()
        sha2 = __import__("hashlib").sha256(wert2.encode()).hexdigest()

        # 2) secret-setzen
        body = {"s3": {"prefix": PREFIX}, "user": "anna", "ns": "demo",
                "name": "provider-key", "wert": wert1, **auth(kp, "secret-setzen", space)}
        st, o = post(sock, "/secret-setzen", body)
        assert st == 200 and o["secret"]["ergebnis"]["eintraege"][0]["sha256"] == sha1, (st, o)
        out(f"[2] SETZEN OK sha={sha1[:12]} version={o['secret']['ergebnis']['eintraege'][0]['version']}")
        run_reader(resp, "anna", "anna-pass-123", "vor-rotation", expect=sha1)

        # 3) secret-liste (nur Namen + Hashes)
        body = {"s3": {"prefix": PREFIX}, "user": "anna", **auth(kp, "secret-liste", space)}
        st, o = post(sock, "/secret-liste", body)
        assert st == 200, (st, o)
        eintraege = o["secret"]["eintraege"]
        assert any(e["name"] == "provider-key" and e["sha256"] == sha1 for e in eintraege), eintraege
        assert "wert" not in json.dumps(o)
        out(f"[3] LISTE OK eintraege={[(e['name'], e['sha256'][:12], e['aktiv']) for e in eintraege]}")

        # 4) secret-rotieren + Reader sieht neuen Wert SOFORT
        body = {"s3": {"prefix": PREFIX}, "user": "anna", "ns": "demo",
                "name": "provider-key", "wert": wert2, **auth(kp, "secret-rotieren", space)}
        st, o = post(sock, "/secret-rotieren", body)
        assert st == 200 and o["secret"]["ergebnis"]["eintraege"][0]["sha256"] == sha2, (st, o)
        out(f"[4] ROTIEREN OK sha={sha2[:12]} version={o['secret']['ergebnis']['eintraege'][0]['version']}")
        r = run_reader(resp, "anna", "anna-pass-123", "nach-rotation", expect=sha2)
        assert sha1 not in r["raw"] and sha2 in r["raw"]

        # 5) secret-revozieren + Reader sieht "deaktiviert" SOFORT
        body = {"s3": {"prefix": PREFIX}, "user": "anna", "ns": "demo",
                "name": "provider-key", **auth(kp, "secret-revozieren", space)}
        st, o = post(sock, "/secret-revozieren", body)
        assert st == 200, (st, o)
        out(f"[5] REVOZIEREN OK aktiv={o['secret']['ergebnis']['eintraege'][0]['aktiv']}")
        run_reader(resp, "anna", "anna-pass-123", "nach-revozierung")
        # Liste zeigt aktiv=false (Wert bleibt, nicht gelöscht)
        st, o = post(sock, "/secret-liste", {"s3": {"prefix": PREFIX}, "user": "anna",
                                             **auth(kp, "secret-liste", space)})
        assert st == 200 and o["secret"]["eintraege"][0]["aktiv"] is False, (st, o)
        out("[5b] LISTE OK aktiv=false (nicht gelöscht)")
    finally:
        p.terminate()
        srvlog.write(p.stdout.read().decode(errors="replace"))
        srvlog.close()
    out("== SECRETMANAGER E2E GRUEN ==")


def phase_s3proof():
    """S3-Beweis via EXISTIERENDEM s3-list: secret.db im eigenen Praefix."""
    clusters = json.load(open(f"{D}/s2/clusters.json"))
    resp = json.load(open(f"{D}/world-response.json"))
    space = resp["space"]
    kp = json.load(open(f"{D}/keys/paths.json"))
    binary = open(f"{D}/operation.bin").read().strip()
    sock = f"{SOCK_DIR}/operation-s3.sock"
    p = start(binary, sock)
    log = open(f"{D}/s3/s3-list-server.log", "w")
    listing = []
    try:
        for c in clusters:
            rel = c["prefix"][len(PREFIX):]
            st, o = post(sock, "/s3-list", {"s3": {"prefix": PREFIX}, "prefix": rel})
            assert st == 200, (st, o)
            secret_objs = [x["key"] for x in o["objects"]]
            st, w = post(sock, "/s3-list", {"s3": {"prefix": PREFIX},
                                            "prefix": f"workspaces/{c['addr_user']}/"})
            assert st == 200, (st, w)
            ws_objs = [x["key"] for x in w["objects"]]
            db_key = c["secret_db_key"]
            assert db_key in secret_objs, (db_key, secret_objs)
            assert db_key not in ws_objs, (db_key, ws_objs)
            listing.append({"user": c["user"], "secret_db_key": db_key,
                            "secret_list": secret_objs, "workspace_list": ws_objs})
            out(f"[s3proof] {c['user']}: {db_key} NUR im secret-cluster "
                f"(workspaces: {len(ws_objs)} Objekte, ohne secret.db)")
        # Secrets-Eintrag ist der einzige Wahrheitsort: ro-Profil liefert
        # exakt den Cluster-Prefix, aus dem der Reader liest.
        env = dict(os.environ, SECRET_S3_CONFIG=S3, SECRET_PREFIX=PREFIX,
                   SECRET_SPACE=space, SECRET_USER_NAME="anna", SECRET_USER_PW="anna-pass-123",
                   SECRET_OUT=f"{D}/reader-tmp")
        r = subprocess.run([f"{TOOLS}/examples/secret_reader"], env=env, capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "READER_OK" in r.stdout
        out("[s3proof] Reader liest Cluster ausschliesslich aus dem secrets-Eintrag")
    finally:
        p.terminate()
        log.write(p.stdout.read().decode(errors="replace"))
        log.close()
    json.dump(listing, open(f"{D}/s3/secret-keys.json", "w"), indent=1)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "prepare"
    {"prepare": phase_prepare, "world": phase_world, "secrets": phase_secrets,
     "s3proof": phase_s3proof}[cmd]()
