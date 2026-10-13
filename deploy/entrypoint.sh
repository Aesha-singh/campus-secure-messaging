#!/bin/sh
# CSCP server container entrypoint.
#
# Creates the mutable state directories and, on first boot, generates a
# self-contained PKI (CA + server + client leaf) so the TLS 1.3 / mTLS listener
# can start with zero manual setup.  The generated material lands in a mounted
# volume (default /app/security/certs) so it survives restarts and can be copied
# to clients.
set -eu

CERTS_DIR="${CSCP_CERTS_DIR:-/app/security/certs}"
USERS_FILE="${CSCP_USERS_FILE:-/app/security/users.yaml}"
mkdir -p /app/data /app/logs "$CERTS_DIR" 2>/dev/null || true

if [ ! -f "$CERTS_DIR/server.pem" ]; then
    if [ -w "$CERTS_DIR" ]; then
        echo "cscp: first boot - generating a local PKI under $CERTS_DIR" >&2
        python -m security.certs --outdir "$CERTS_DIR"
    else
        echo "cscp: ERROR no certificate in $CERTS_DIR and it is not writable." >&2
        echo "cscp: run 'make certs' on the host, then 'docker compose up' again." >&2
        exit 1
    fi
fi

# Provision demo accounts (Argon2id) on first boot so the stack is usable
# immediately.  Override the password with CSCP_DEMO_PASSWORD.  This file is
# generated inside the container; supply your own users.yaml for real use.
if [ ! -f "$USERS_FILE" ]; then
    echo "cscp: provisioning demo users (alice, bob) -> $USERS_FILE" >&2
    python - "$USERS_FILE" "${CSCP_DEMO_PASSWORD:-campus-demo1}" <<'PY'
import sys
from security.auth import provision_default_db
path, password = sys.argv[1], sys.argv[2]
provision_default_db(path, {"alice": password, "bob": password},
                     roles={"alice": "staff", "bob": "member"})
PY
fi

exec "$@"
