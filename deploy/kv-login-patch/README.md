# kv-login UDS/udsv3-Patch

Der Login-Dienst liegt im Schwester-Repo `/data/kronvault/kv-login` (dort
untracked). Diese Dateien sind die deployte Fassung: `--uds` statt
`--bind`, udsv3-Fassade (Kontext `kv-login`), Socket 0600.

Deployment:
```
cp -a src Cargo.toml /data/kronvault/kv-login/
cd /data/kronvault/kv-login && cargo build --release --bin kv-login
# systemd: --uds /data/z8run/kv-login.sock, ExecStartPost chgrp z8run/chmod 660
```
