# Docker Deployment Guide for Mega-Analyzer

[Русский](DOCKER_DEPLOYMENT.ru.md)

This guide provides comprehensive instructions for deploying Mega-Analyzer using Docker and Docker Compose.

## Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- At least 8GB of RAM
- 50GB of free disk space
- Linux kernel with KVM support (for Android emulator)

## Quick Start

The only path guaranteed to work out of the box is building and running the
single `analyzer` image — the shipped `Dockerfile` produces one static,
`CGO_ENABLED=0` pure-Go binary with no database, cache, or emulator
dependency (see [BUILD.md](BUILD.md)). Everything under "Optional /
Illustrative Extra Services" below is example wiring for your own
orchestration, not a supported or required deployment path.

### 1. Build the Docker Image

```bash
# Build the main Mega-Analyzer image
docker build -t mega-analyzer:latest .

# Verify the build
docker images | grep mega-analyzer
```

### 2. Run the analyzer

```bash
# Run a single analysis and exit
docker run --rm \
  -v "$(pwd)/workspace:/home/analyzer/workspace:ro" \
  -v "$(pwd)/reports:/home/analyzer/reports:rw" \
  mega-analyzer:latest \
  -t /home/analyzer/workspace/app.apk --ml-patch --crackpoint-analysis -o /home/analyzer/reports
```

Or, using `docker-compose.yml`:

```bash
# First run: copy the example and set MEGA_ANALYZER_API_TOKEN in .env.
# Generate a random token with: openssl rand -hex 32
cp .env.example .env

# Starts only the core analyzer service — the extra sidecars below are
# gated behind Compose profiles and are NOT started by a bare `up`.
docker-compose up -d

# Check status / logs
docker-compose ps
docker-compose logs -f analyzer

# Enter the container and run the analyzer manually
docker-compose exec analyzer bash
analyzer -t /home/analyzer/workspace/app.apk --ml-patch --crackpoint-analysis -o /home/analyzer/reports
```

The API is available at `http://127.0.0.1:5000`. Pass the token from `.env`
in the `Authorization: Bearer <token>` or `X-Mega-Analyzer-Token` header:

```bash
curl -H 'Authorization: Bearer <token from .env>' http://127.0.0.1:5000/api/v1/status
```

Inside the container the API listens on `0.0.0.0`, while Docker publishes
the port only on the host's loopback interface. A missing token prevents
Compose from starting the service. Completed reports and uploaded artifacts
are stored under `./reports/api`; local scan targets must be inside `./workspace`.

## Configuration

### Environment Variables

The analyzer binary reads its own config from `ANALYZER_*`-prefixed
environment variables (see [FlagiFiles.md](../FlagiFiles.md) and
[USAGE.md](USAGE.md) for the full/short reference) — for example:

```yaml
environment:
  - ANALYZER_OUTPUT_DIR=/home/analyzer/reports
  - ANALYZER_WORKERS=4
  - ANALYZER_LOG_LEVEL=info
  - ANALYZER_PROFILE=deep
```

The REST server uses separate `MEGA_ANALYZER_*` settings, supplied by Compose:

| Variable | Container value / purpose |
| --- | --- |
| `MEGA_ANALYZER_API_BIND` | `0.0.0.0` for Docker port forwarding |
| `MEGA_ANALYZER_API_TOKEN` | Required shared secret from `.env` |
| `MEGA_ANALYZER_SCAN_ROOT` | `/home/analyzer/workspace`, allowed local inputs |
| `MEGA_ANALYZER_JOB_ROOT` | `/home/analyzer/reports/api`, jobs and artifacts |
| `MEGA_ANALYZER_SCAN_CONCURRENCY` | `4`, simultaneous API scans |

ML/MITM/sandbox features are controlled by CLI flags (`--ml-patch`,
`-android-sandbox`, etc.), not environment toggles.

### Volume Mounts

- `./workspace`: Input APK/DEX files
- `./reports`: Output analysis reports
- `./configs`: Configuration files

## Optional / Illustrative Extra Services

`docker-compose.yml` also defines an mitmproxy sidecar, an Android-emulator
container, PostgreSQL, and Redis, each gated behind its own Compose
[profile](https://docs.docker.com/compose/how-tos/profiles/) (`mitm`,
`android`, `postgres`, `redis`) so a plain `docker-compose up -d` never
starts them. **None of these are consumed by the analyzer binary** — it has
no database or cache client, and does not read MITM/sandbox env toggles.
They're left in as example wiring for anyone who wants to build their own
orchestration around Mega-Analyzer, not a supported path.

To enable one or more, add the required passwords to the existing `.env`
(see [`.env.example`](../.env.example)) and pass the profile(s) explicitly.
PostgreSQL and Redis reject an empty password when their containers start;
their passwords are not needed for the core analyzer alone.

```bash
# Edit POSTGRES_PASSWORD / REDIS_PASSWORD in .env, keeping the API token.

docker-compose --profile postgres up -d   # + PostgreSQL
docker-compose --profile redis up -d      # + Redis
docker-compose --profile mitm up -d       # + mitmproxy
docker-compose --profile android up -d    # + Android emulator (Linux/KVM host only)
```

### MITM Proxy (optional, not wired to the analyzer)

```bash
# Access mitmproxy web interface
# Navigate to http://localhost:8081

# Configure proxy in Android emulator
adb shell settings put global http_proxy 127.0.0.1:8080
```

### Android Emulator (optional, not wired to the analyzer)

```bash
# Connect to emulator
docker-compose exec analyzer adb connect android-emulator:5555

# List connected devices
docker-compose exec analyzer adb devices

# Install test APK
docker-compose exec analyzer adb install /home/analyzer/workspace/test.apk
```

### PostgreSQL (optional, not wired to the analyzer)

The analyzer does not read from or write to this database itself — it's
provided only as a starting point if you want to persist results yourself.

```bash
# Connect to database
docker-compose exec postgres psql -U analyzer -d mega_analyzer

# Example query
SELECT * FROM analysis_results ORDER BY created_at DESC LIMIT 10;
```

### Redis (optional, not wired to the analyzer)

The analyzer does not use Redis for caching or sessions itself — it's
provided only as a starting point for your own tooling.

```bash
# Connect to Redis
docker-compose exec redis redis-cli

# Check cache statistics
DBSIZE
INFO stats
```

## Performance Tuning

### Resource Limits

Adjust resource limits in `docker-compose.yml`:

```yaml
deploy:
  resources:
    limits:
      cpus: '8'        # Increase for faster analysis
      memory: 16G      # Increase for large APKs
    reservations:
      cpus: '4'
      memory: 8G
```

### Worker Threads

Configure worker threads for parallel analysis:

```bash
docker-compose exec analyzer analyzer --workers 8
```

### GPU Acceleration (Optional)

To enable GPU acceleration for ML models:

```yaml
services:
  analyzer:
    runtime: nvidia
    environment:
      - CUDA_VISIBLE_DEVICES=0
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs analyzer

# Verify image
docker inspect mega-analyzer:latest

# Rebuild image
docker-compose build --no-cache
```

### Out of Memory

```bash
# Increase Docker memory limit
# Edit Docker Desktop settings or:
docker update --memory 16g mega-analyzer
```

### Network Issues

```bash
# Check network connectivity
docker-compose exec analyzer ping 8.8.8.8

# Verify MITM proxy
docker-compose exec analyzer curl -x http://mitm-proxy:8080 https://example.com
```

### Android Emulator Not Connecting

```bash
# Check emulator status
docker-compose exec analyzer adb devices

# Restart emulator
docker-compose restart android-emulator

# Check logs
docker-compose logs android-emulator
```

## Cleanup

```bash
# Stop all services
docker-compose down

# Remove volumes
docker-compose down -v

# Remove images
docker rmi mega-analyzer:latest

# Clean up unused resources
docker system prune -a
```

## Production Deployment

### Security Considerations

1. **Use private registry**: Push images to private Docker registry
2. **Sign images**: Use Docker Content Trust for image signing
3. **Network isolation**: Run containers on isolated network
4. **Secret management**: Use Docker secrets for sensitive data
5. **Resource limits**: Set appropriate CPU and memory limits

### Kubernetes Deployment

Example Kubernetes deployment manifest:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mega-analyzer
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mega-analyzer
  template:
    metadata:
      labels:
        app: mega-analyzer
    spec:
      containers:
      - name: analyzer
        image: mega-analyzer:latest
        resources:
          requests:
            memory: "4Gi"
            cpu: "2"
          limits:
            memory: "8Gi"
            cpu: "4"
        volumeMounts:
        - name: workspace
          mountPath: /home/analyzer/workspace
        - name: reports
          mountPath: /home/analyzer/reports
      volumes:
      - name: workspace
        persistentVolumeClaim:
          claimName: analyzer-workspace
      - name: reports
        persistentVolumeClaim:
          claimName: analyzer-reports
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Analysis

on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Build Docker image
        run: docker build -t mega-analyzer:ci .
      
      - name: Run analysis
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/home/analyzer/workspace \
            -v ${{ github.workspace }}/reports:/home/analyzer/reports \
            mega-analyzer:ci \
            analyzer -t /home/analyzer/workspace/app.apk -o /home/analyzer/reports
      
      - name: Upload reports
        uses: actions/upload-artifact@v2
        with:
          name: analysis-reports
          path: reports/
```

### GitLab CI Example

```yaml
analyze:
  image: mega-analyzer:latest
  script:
    - analyzer -t $CI_PROJECT_DIR/app.apk -o $CI_PROJECT_DIR/reports
  artifacts:
    paths:
      - reports/
    expire_in: 30 days
```

## Monitoring

### Health Checks

Docker Compose includes health checks for all services:

```bash
# Check service health
docker-compose ps

# View health check logs
docker inspect mega-analyzer | grep -A 20 "Health"
```

### Logging

Centralized logging configuration:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "100m"
    max-file: "10"
```

### Metrics

Monitor container metrics:

```bash
# Real-time statistics
docker stats mega-analyzer

# Historical data
docker stats --no-stream mega-analyzer
```

## Support and Documentation

- [Official Docker Documentation](https://docs.docker.com/)
- [Docker Compose Reference](https://docs.docker.com/compose/compose-file/)
- [Mega-Analyzer README](../README.md)
- [Архитектура](ARCHITECTURE.md)
