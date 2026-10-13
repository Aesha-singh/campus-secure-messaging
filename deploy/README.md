# Deployment guide

Two supported paths: **Docker Compose** (fastest) and a **systemd** service on
a Linux host.  Both run the same `cscp-server` entry point with TLS 1.3 + mTLS.

## 0. Generate the PKI (once)

```bash
python -m security.certs --outdir security/certs --ip 203.0.113.10 --host messaging.campus.edu
ls security/certs   # ca.pem, ca.key, server.pem, server.key, cscp-client.pem/.key
```

Keep `ca.key` **off the server** after signing (it is the trust anchor).  Distribute
`ca.pem` + a client cert/key pair to each device.  The client opts into mTLS with
`require_tls: true` and the `ca_file`/`certfile`/`keyfile` paths.

## 1a. Docker Compose

```bash
# from deploy/
cat > .env <<'EOF'
CSCP_SERVER_SECRET=$(python -c 'import secrets;print(secrets.token_hex(32))')
CSCP_ADMIN_PASSWORD=$(python -c 'import secrets;print(secrets.token_urlsafe(24))')
CSCP_ADMIN_TOKEN=$(python -c 'import secrets;print(secrets.token_urlsafe(24))')
EOF
docker compose up -d --build
docker compose logs -f cscp
```

The image is multi-stage-free, runs as non-root (`cscp`), drops all Linux
capabilities, and exposes:
- `9443/tcp` -- CSCP protocol (publish this through your firewall)
- `127.0.0.1:9444/tcp` -- admin dashboard (bound to loopback in compose)

Health: `docker inspect --format '{{.State.Health.Status}}' <container>`.

## 1b. systemd (bare host)

```bash
sudo useradd --system --home /opt/cscp --shell /usr/sbin/nologin cscp
sudo mkdir -p /opt/cscp /etc/cscp
sudo cp -r . /opt/cscp && cd /opt/cscp
python -m venv .venv && .venv/bin/pip install .
sudo chown -R cscp:cscp /opt/cscp

sudo cp deploy/server.prod.yaml /etc/cscp/server.yaml
sudo cp deploy/cscp-server.service /etc/systemd/system/cscp-server.service
sudo install -m 0640 -o root -g cscp /dev/null /etc/cscp/cscp.env
sudo tee /etc/cscp/cscp.env >/dev/null <<'EOF'
CSCP_SERVER_SECRET=change-me
CSCP_ADMIN_PASSWORD=change-me
CSCP_ADMIN_TOKEN=change-me
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now cscp-server
systemctl status cscp-server
journalctl -u cscp-server -f
```

## 2. Verify

```bash
# CSCP port is open and offering TLS 1.3:
openssl s_client -connect localhost:9443 -tls1_3 -servername localhost </dev/null 2>/dev/null | head

# Admin plane (loopback): token required for /metrics
curl -s -H "Authorization: Bearer $CSCP_ADMIN_TOKEN" http://127.0.0.1:9444/metrics | python -m json.tool
curl -s http://127.0.0.1:9444/health
```

## 3. Operations notes

- **Firewall**: allow only `9443/tcp` from campus subnets; keep `9444` on
  loopback (or put it behind an SSH tunnel / reverse proxy with auth).
- **Backups**: the durable state is `data/campus.db` (SQLite, WAL) and the
  relayed blobs under `data/blobs/` (opaque ciphertext).  Snapshot both.
- **Rotation**: `CSCP_SERVER_SECRET` rotation invalidates session-resume tokens
  (users re-authenticate); certificates rotate via a new `security.certs` run +
  service reload.
- **Scaling**: the server is single-process/event-loop.  Horizontally scale by
  running several nodes behind a TCP load balancer (L4), with a shared message
  store; sticky sessions are not required because the protocol is stateless
  between frames apart from the auth token.
- **Observability**: scrape `GET /metrics` (JSON) behind the bearer token; the
  payload mirrors `server.metrics.snapshot()`.