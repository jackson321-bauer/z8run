#!/usr/bin/env python3
"""Erzeugt das KV3-Login-WebAuthn-Canvas (zwei Hook-Pfade).

Kein Secret im Flow: S3-Zugang kommt aus /etc/z8run/kv3-s3.json.
`--prefix` backt den Test-Prefix in kv3-open (Login-Flow, kein Request-
Override für S3-Hosts).
"""

from __future__ import annotations

import argparse
import datetime
import json
import uuid

S3 = "/etc/z8run/kv3-s3.json"
CHALLENGE_DIR = "/data/z8run/login-challenges"
PROXY_SOCK = "/data/z8run/kv3-proxy.sock"


def node(nid, typ, label, cfg, *, error=True, trigger=False, out=False):
    data = {"type": typ, "label": label, "config": cfg}
    if trigger:
        data["inputs"] = []
        data["outputs"] = [{"id": "output", "name": "Output", "type": "object"}]
    elif out:
        data["inputs"] = [{"id": "input", "name": "Input", "type": "any"}]
        data["outputs"] = []
    else:
        data["inputs"] = [{"id": "input", "name": "Input", "type": "any"}]
        data["outputs"] = (
            [
                {"id": "output", "name": "Output", "type": "object"},
                {"id": "error", "name": "Error", "type": "any"},
            ]
            if error
            else [{"id": "output", "name": "Output", "type": "object"}]
        )
    return {"id": nid, "type": "z8node", "position": {"x": 0, "y": 0}, "data": data}


def edge(src, dst, port="output"):
    return {
        "id": f"e-{src}-{port}-{dst}",
        "source": src,
        "sourceHandle": port,
        "target": dst,
        "targetHandle": "input",
    }


def build(prefix: str):
    # /login zuerst: z8-export CLI nutzt den ersten Trigger.
    nodes = [
        node("in", "unix-in", "POST /login", {"method": "POST", "path": "/login"}, trigger=True),
        node("addr-space", "kv3-adresse", "Space-Adresse", {
            "ebene": "space", "namePath": "req.body.space",
            "spacePath": "req.body.space", "sharedPath": ""}),
        node("addr-user", "kv3-adresse", "User-Adresse", {
            "ebene": "user", "namePath": "req.body.user",
            "spacePath": "req.body.space", "sharedPath": ""}),
        node("j", "join", "Adressen zusammenführen", {"inputs": 2, "timeoutMs": 15000}),
        node("open", "kv3-open", "Passwort-Box -> Provider-Shard", {
            "s3Config": S3, "saltField": "salt_user", "bucket": "", "prefix": prefix + "b2b/",
            "passwortPath": "req.body.password", "targetAddrPath": "addr_user",
            "basePath": "addr_space"}),
        node("verify", "webauthn-verify", "Assertion + Client-Shard", {
            "s3Config": S3, "addrPath": "addr_user", "challengeDir": CHALLENGE_DIR,
            "rpId": "localhost", "origin": "http://localhost:7700"}),
        node("master", "kv3-master", "Shamir 2-of-2 -> Master", {}),
        node("sess", "unix-out", "Session an Proxy-UDS", {
            "socketPath": PROXY_SOCK, "method": "POST", "path": "/session",
            "bodyPath": "proxy_session", "timeoutMs": 5000,
            "preserveInput": True, "stripFields": "proxy_session"}, error=True),
        node("ok", "http-out", "200 Login OK", {"statusCode": 200}, out=True),
        node("err-j", "http-out", "401 Join", {"statusCode": 401}, out=True),
        node("err-open", "http-out", "401 Open", {"statusCode": 401}, out=True),
        node("err-verify", "http-out", "401 Verify", {"statusCode": 401}, out=True),
        node("err-master", "http-out", "401 Master", {"statusCode": 401}, out=True),
        node("err-sess", "http-out", "401 Session", {"statusCode": 401}, out=True),
        node("err-addrspace", "http-out", "401 Space", {"statusCode": 401}, out=True),
        node("err-addraddr", "http-out", "401 User", {"statusCode": 401}, out=True),

        node("in-ch", "unix-in", "POST /challenge", {"method": "POST", "path": "/challenge"}, trigger=True),
        node("ch", "webauthn-challenge", "Challenge ausstellen", {
            "challengeDir": CHALLENGE_DIR, "rpId": "localhost",
            "origin": "http://localhost:7700"}, error=True),
        node("out-ch", "http-out", "200 Challenge", {"statusCode": 200}, out=True),
        node("err-ch", "http-out", "400 Challenge", {"statusCode": 400}, out=True),
    ]
    edges = [
        edge("in", "addr-space"), edge("in", "addr-user"),
        edge("addr-space", "j"), edge("addr-user", "j"),
        edge("j", "open"), edge("open", "verify"), edge("verify", "master"),
        edge("master", "sess"), edge("sess", "ok"),
        edge("j", "err-j", "error"), edge("open", "err-open", "error"),
        edge("verify", "err-verify", "error"), edge("master", "err-master", "error"),
        edge("sess", "err-sess", "error"), edge("addr-space", "err-addrspace", "error"),
        edge("addr-user", "err-addraddr", "error"),
        edge("in-ch", "ch"), edge("ch", "out-ch"),
        edge("ch", "err-ch", "error"),
    ]
    flow_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "z8-kv3-login-webauthn"))
    now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "id": flow_id,
        "created_at": now,
        "updated_at": now,
        "name": "KV3-Login-WebAuthn",
        "description": "Login v2: Passwort + WebAuthn-Assertion + Client-geöffneter HW-Shard",
        "version": "0.1.0",
        "nodes": [],
        "edges": [],
        "config": {"credentials": [], "env_vars": {}, "timeout_ms": 0, "buffer_size": 0},
        "status": "idle",
        "metadata": {"positions": {"canvas_nodes": nodes, "canvas_edges": edges}, "zoom": 1.0},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--prefix", default="sim2/welt2/")
    args = ap.parse_args()
    with open(args.out, "w") as f:
        json.dump(build(args.prefix), f, indent=2)
    print(args.out)


if __name__ == "__main__":
    main()
