# sqli-raw lab - intentionally vulnerable, local-only.
# See README.md. Never expose this beyond 127.0.0.1.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Build deps required to compile mysqlclient against MySQL's C client lib.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        default-libmysqlclient-dev \
        build-essential \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 0.0.0.0 here is fine/expected: the 127.0.0.1-only guarantee comes from the
# docker-compose port mapping "127.0.0.1:18007:18007", not from this bind.
EXPOSE 18007

CMD ["python", "manage.py", "runserver", "0.0.0.0:18007"]
