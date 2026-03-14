FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /build

COPY pyproject.toml setup.py README.md ./
COPY guard/ guard/

COPY examples/advanced_app/pyproject.toml /app/pyproject.toml

WORKDIR /app

RUN uv venv .venv && \
    uv pip install --python .venv/bin/python /build && \
    uv pip install --python .venv/bin/python gunicorn uvicorn

FROM python:3.12-slim

RUN groupadd --system guard && \
    useradd --system --gid guard --create-home guard

WORKDIR /app

COPY --from=builder --chown=guard:guard /app/.venv /app/.venv

COPY --chown=guard:guard examples/advanced_app/app/ /app/app/
COPY --chown=guard:guard examples/advanced_app/gunicorn.conf.py /app/gunicorn.conf.py

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER guard

EXPOSE 8000

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app.main:app"]
