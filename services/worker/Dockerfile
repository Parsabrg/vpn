FROM python:3.14.6-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --gid 10003 nebula-worker \
    && useradd --uid 10003 --gid nebula-worker --no-create-home --shell /usr/sbin/nologin nebula-worker

COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir .

USER 10003:10003

CMD ["python", "-m", "nebula_worker.main"]
