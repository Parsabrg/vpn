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

RUN addgroup -S -g 10002 nebula-agent \
    && adduser -S -D -H -u 10002 -G nebula-agent -s /sbin/nologin nebula-agent

COPY pyproject.toml README.md ./
COPY src ./src
# pip is not needed at runtime, and the copy in the base image carries its
# own old certifi, urllib3, msgpack and setuptools that scanners flag.
RUN python -m pip install --no-cache-dir .     && python -m pip uninstall --yes pip setuptools wheel

USER 10002:10002
EXPOSE 9443

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9443/healthz', timeout=2)"]

CMD ["uvicorn", "nebula_agent.main:app", "--host", "0.0.0.0", "--port", "9443", "--no-access-log"]
