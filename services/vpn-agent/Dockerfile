FROM python:3.14.6-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --gid 10002 nebula-agent \
    && useradd --uid 10002 --gid nebula-agent --no-create-home --shell /usr/sbin/nologin nebula-agent

COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir .

USER 10002:10002
EXPOSE 9443

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9443/healthz', timeout=2)"]

CMD ["uvicorn", "nebula_agent.main:app", "--host", "0.0.0.0", "--port", "9443", "--no-access-log"]
