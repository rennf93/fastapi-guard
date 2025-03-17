FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    libsodium23 \
    wget \
    build-essential \
    libffi-dev \
    curl

WORKDIR /app

ENV PIP_NO_CACHE_DIR=false \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=10 \
    POETRY_VERSION=1.5.1 \
    POETRY_HOME="/home/user/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENV VENV_PATH="/app/.venv"
ENV PATH="${POETRY_HOME}/bin:${VENV_PATH}/bin:${PATH}"

RUN curl -sSL https://install.python-poetry.org | python3 -
COPY pyproject.toml poetry.lock* /app/

RUN poetry install --no-root

# Copy library code and examples
COPY guard/ /app/guard/
COPY tests/ /app/tests/
COPY examples/ /app/examples/

# Create directory for data storage
RUN mkdir -p /app/data/ipinfo
