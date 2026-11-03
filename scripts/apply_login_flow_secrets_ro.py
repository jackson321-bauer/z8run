#!/usr/bin/env python3
"""V1.2-Flow-Wiring (idempotent): fuegt dem Login-Flow den Knoten
`kv3-secrets-ro` VOR `kv3-open` hinzu und exportiert den Flow als Snapshot.

Warum VOR kv3-open: kv3-open entfernt das Login-Passwort aus dem Payload;
nur davor ist der mit dem Passwort versiegelte secrets-ro-Block oeffenbar.
Der Knoten setzt das additive Handoff-Feld `secrets` (ro-Profil).

Aufruf: python3 scripts/apply_login_flow_secrets_ro.py \
          [--db /data/z8run/data/z8run.db] [--flow-id 01a18933-...] \
          [--out flows/KV3-Login-WebAuthn.flow.json]
"""
import argparse, json, sqlite3, sys

def erweitere(d: dict) -> bool:
    pos = d["metadata"]["positions"]
    nodes, edges = pos["canvas_nodes"], pos["canvas_edges"]
    if any(n["data"]["type"] == "kv3-secrets-ro" for n in nodes):
        return False
    op = next(n for n in nodes if n["data"]["type"] == "kv3-open")
    oc = op["data"].get("config", {})
    sec = {
        "data": {
            "config": {
                "s3Config": oc.get("s3Config", "/etc/z8run/kv3-s3.json"),
                "bucket": oc.get("bucket", ""),
                "prefix": oc.get("prefix", ""),
                "passwortPath": oc.get("passwortPath", "req.body.password"),
                "targetAddrPath": oc.get("targetAddrPath", "addr_user"),
            },
            "inputs": [{"id": "input", "name": "Input", "type": "any"}],
            "label": "secrets-ro-Block (optional) -> ro-Profil",
            "outputs": [
                {"id": "output", "name": "Profil", "type": "object"},
                {"id": "error", "name": "Error", "type": "any"},
            ],
            "type": "kv3-secrets-ro",
        },
        "id": "sec-ro",
        "position": {"x": op["position"]["x"] - 280, "y": op["position"]["y"]},
        "type": "z8node",
    }
    e = next((e for e in edges if e["target"] == "open" and e["source"] == "j"), None)
    if e is None:
        raise SystemExit("j->open-Kante fehlt")
    e["target"], e["targetHandle"] = "sec-ro", "input"
    err_t = next((x["target"] for x in edges if x["source"] == "open" and x["sourceHandle"] == "error"), "err-open")
    edges.append({"id": "e-sec-open", "source": "sec-ro", "sourceHandle": "output", "target": "open", "targetHandle": "input"})
    edges.append({"id": "e-sec-err", "source": "sec-ro", "sourceHandle": "error", "target": err_t, "targetHandle": "input"})
    nodes.append(sec)
    return True

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="/data/z8run/data/z8run.db")
    ap.add_argument("--flow-id", default="01a18933-f5b2-74be-a57c-9f74cb0e9426")
    ap.add_argument("--out", default="flows/KV3-Login-WebAuthn.flow.json")
    a = ap.parse_args()
    c = sqlite3.connect(a.db)
    row = c.execute("select data from flows where id=?", (a.flow_id,)).fetchone()
    if not row:
        return sys.exit(f"Flow {a.flow_id} nicht in DB")
    d = json.loads(row[0])
    changed = erweitere(d)
    if changed:
        c.execute("update flows set data=? where id=?", (json.dumps(d), a.flow_id))
        c.commit()
    c.close()
    with open(a.out, "w") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    print(f"flow={a.flow_id} secrets_ro={'neu' if changed else 'schon vorhanden'} out={a.out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
