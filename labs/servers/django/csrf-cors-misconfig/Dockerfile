# Intentionally vulnerable lab image (CWE-352: CSRF, compounded by a
# permissive CORS misconfiguration). Local lab use only.
# See README.md for the vulnerability write-up and exploit instructions.

FROM python:3.12-slim

# Build deps for mysqlclient (libmysqlclient-dev + a C compiler), removed
# from the final layer is not attempted here since this is a throwaway
# local lab image, not a size-optimized production one.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        default-libmysqlclient-dev \
        pkg-config \
        gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# The server binds 127.0.0.1:18009 by default when run directly with
# manage.py runserver; 0.0.0.0 is used here only so the port is reachable
# from outside the container -- keep the published docker-compose port
# mapping bound to the host's loopback interface, e.g.:
#   ports:
#     - "127.0.0.1:18009:18009"
EXPOSE 18009

CMD ["python", "manage.py", "runserver", "0.0.0.0:18009"]
