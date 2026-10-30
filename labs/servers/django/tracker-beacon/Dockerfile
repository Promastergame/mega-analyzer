# tracker-beacon lab server — INTENTIONALLY INSECURE, LOCAL LAB USE ONLY.
# Undisclosed telemetry / silent data exfiltration lab (CWE-359 flavor).
# See README.md. Never deploy this image anywhere but an isolated sandbox.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# mysqlclient build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        default-libmysqlclient-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 18010

CMD ["python", "manage.py", "runserver", "0.0.0.0:18010"]
