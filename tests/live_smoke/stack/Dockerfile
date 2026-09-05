FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

COPY wheels/ /wheels/

RUN uv venv .venv && \
    uv pip install --python .venv/bin/python /wheels/*.whl gunicorn "uvicorn[standard]" redis guard-agent httpx \
        opentelemetry-sdk opentelemetry-exporter-otlp-proto-http logfire && \
    .venv/bin/python -c "import guard_core, importlib.metadata as m; print('guard-core', m.version('guard-core'), guard_core.__file__)" && \
    .venv/bin/python -c "import guard, importlib.metadata as m; print('fastapi-guard', m.version('fastapi-guard'), guard.__file__)"

COPY app/ /app/app/
COPY gunicorn.conf.py /app/

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app.main:app"]
