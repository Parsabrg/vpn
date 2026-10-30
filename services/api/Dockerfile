FROM python:3.14.8-alpine3.24 AS runtime

# Alpine security updates on top of whatever the base image was last built
# with. The CVE scan runs with --ignore-unfixed, so it fails only on
# vulnerabilities Alpine has already published a fix for -- the gap it
# catches is the base image being older than the fix, and taking the updates
# here closes it. Deliberately unpinned: pinning would mean editing this file
# for every CVE anywhere in the base. Alpine rather than Debian slim: the
# image is far smaller, and every dependency ships a musllinux wheel, so
# nothing is compiled.
RUN apk upgrade --no-cache

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN addgroup -S -g 10001 nebula \
    && adduser -S -D -H -u 10001 -G nebula -s /sbin/nologin nebula

COPY pyproject.toml README.md ./
COPY alembic.ini ./
COPY alembic ./alembic
COPY src ./src
# pip is not needed at runtime, and the copy in the base image carries its
# own old certifi, urllib3, msgpack and setuptools that scanners flag.
RUN python -m pip install --no-cache-dir .     && python -m pip uninstall --yes pip setuptools wheel

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

# Writable state this installation generates for itself -- the deployment
# secret above all. Created here so the directory exists and is owned by the
# service user even when no volume is mounted over it; a named volume
# inheriting this ownership is what makes the secret survive `docker compose
# down` without the container needing to run as root to create it.
RUN mkdir -p /var/lib/nebula && chown 10001:10001 /var/lib/nebula
VOLUME ["/var/lib/nebula"]

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

# The entrypoint prepares the installation and then execs this, so the
# server still runs as PID 1 and still receives signals directly.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["uvicorn", "nebula_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
