# Deployment guide

Three supported paths: a **turnkey local stack** (fastest), **Docker Compose**
on a server, and a **systemd** service on a Linux host.  All run the same
`cscp-server` entry point with TLS 1.3 + mTLS.

## Quick start -- turnkey local stack

From the repo root, one command (needs Docker Desktop / Engine):

```bash
make up                 # copies deploy/.env.example -> deploy/.env, then builds + starts
make client-stack       # launches the PyQt6 client against it (TLS 1.3 + mTLS)
make logs               # follow server logs
make down               # stop
```

On first boot the container **generates its own PKI** (CA + server + client
leaf) into `security/certs/` and **provisions demo accounts**, so TLS 1.3 +
mTLS and login work with zero manual setup.  Edit `deploy/.env` to replace the
placeholder secrets before using it for anything real.

Demo logins (Argon2id backend, password `CSCP_DEMO_PASSWORD`, default
`campus-demo1`): **`alice`** and **`bob`**.

| Endpoint | Address |
|---|---|
| CSCP protocol (TLS 1.3 + mTLS) | `9443/tcp` |
| Admin dashboard (loopback) | `http://127.0.0.1:9444` |

> On Linux the bind-mounted directories are owned by your host user; if the
> container cannot write the PKI, run `make certs` on the host first (or
> `sudo chown -R 999:999 security/certs data logs`).  On macOS Docker Desktop
> this is not needed.

## 0. Generate the PKI (once, for a real deployment)

For a public server, generate certs whose SANs match your hostname/IP rather
than relying on the container's local bootstrap:

```bash
python -m security.certs --outdir security/certs --ip 203.0.113.10 --host messaging.campus.edu
ls security/certs   # ca.pem, ca.key, server.pem, server.key, cscp-client.pem/.key
```

Keep `ca.key` **off the server** after signing (it is the trust anchor).  Distribute
`ca.pem` + a client cert/key pair to each device.  The client opts into mTLS with
`require_tls: true` and the `ca_file`/`certfile`/`keyfile` paths.

## 1a. Docker Compose (server)

```bash
# from deploy/
cp .env.example .env    # then edit the three secrets
docker compose up -d --build
docker compose logs -f cscp
```

The image runs as non-root (`cscp`), drops all Linux
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