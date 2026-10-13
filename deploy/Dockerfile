# CSCP server image -- TLS 1.3 messaging + store-and-forward file relay.
# Build from the repository root:  docker build -f deploy/Dockerfile -t cscp-server .
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    CSCP_CONFIG=/app/config/config.yaml

WORKDIR /app

# OS deps: ca-certificates for outbound TLS trust; curl for the healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first (better layer caching), then the project.
COPY pyproject.toml README.md ./
COPY protocol server security messaging client ./
RUN pip install --no-cache-dir .

# Runtime config + mutable state directories, owned by the unprivileged user.
COPY config ./config
RUN groupadd --system cscp \
    && useradd --system --gid cscp --home /app --shell /usr/sbin/nologin cscp \
    && mkdir -p /app/data /app/logs /app/security/certs \
    && chown -R cscp:cscp /app

USER cscp

# 9443 = CSCP (TLS 1.3, mTLS);  9444 = HTTP admin dashboard (metrics/health).
EXPOSE 9443 9444

# Liveness via the admin /health endpoint (no secrets, always 200).
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9444/health', timeout=3).status==200 else 1)"

ENTRYPOINT ["cscp-server"]
CMD ["--config", "/app/config/config.yaml"]