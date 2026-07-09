FROM python:3.12-slim

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

COPY pyproject.toml uv.lock* ./
COPY src/ ./src/
COPY README.md ./

RUN uv sync --frozen --no-dev

ENTRYPOINT ["uv", "run", "python", "-m", "infrahub_consumer"]
