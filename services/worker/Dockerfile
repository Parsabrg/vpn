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

RUN addgroup -S -g 10003 nebula-worker \
    && adduser -S -D -H -u 10003 -G nebula-worker -s /sbin/nologin nebula-worker

COPY pyproject.toml README.md ./
COPY src ./src
# pip is not needed at runtime, and the copy in the base image carries its
# own old certifi, urllib3, msgpack and setuptools that scanners flag.
RUN python -m pip install --no-cache-dir .     && python -m pip uninstall --yes pip setuptools wheel

USER 10003:10003

CMD ["python", "-m", "nebula_worker.main"]
