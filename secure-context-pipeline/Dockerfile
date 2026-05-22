# Python 3.11 gives reliable wheels for the full Presidio + spaCy NER stack.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Build tools needed by some spaCy/Presidio transitive deps.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first (better layer caching).
COPY requirements.txt requirements-nlp.txt ./
RUN pip install --upgrade pip \
    && pip install -r requirements-nlp.txt \
    && python -m spacy download en_core_web_lg

# Project source. Install the API + postgres extras so the service (gunicorn +
# uvicorn workers) and the optional Postgres vault backend are available.
COPY . .
RUN pip install -e .[api,postgres]

# Default: run the full test suite. Override the command to run the demo, e.g.
#   docker compose run --rm app python demo.py
CMD ["pytest", "tests/", "-v"]
