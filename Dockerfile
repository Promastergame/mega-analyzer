# syntax=docker/dockerfile:1
#
# Mega-Analyzer — Linux container image.
#
# The default image is a lean, fully static, pure-Go build (CGO disabled), so it
# runs on any glibc/musl Linux without extra runtime libraries. The optional
# native engines — OmniSec (Rust) and the SIMD ML runtime (Zig) — are gated
# behind Go build tags and are NOT included here; see docs/BUILD.md for the
# full native build on Windows/Linux.

# ── Build stage ──────────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.27.3 AS builder

WORKDIR /build

# Version string baked into the binaries. Override at build time:
#   docker build --build-arg VERSION=v1.0.0-beta.1 -t mega-analyzer .
ARG VERSION=1.0.0-beta.1
ARG COMMIT=unknown
ARG BUILD_DATE
ARG TARGETOS
ARG TARGETARCH

# Download modules first so they cache independently of source changes.
COPY go.mod go.sum ./
RUN go mod download

# Application source.
COPY pkg/ ./pkg/

# Static, pure-Go binaries — no cgo means no libc/libssl runtime dependency.
ENV CGO_ENABLED=0
RUN GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -trimpath -ldflags="-s -w -X main.Version=${VERSION} -X main.CommitHash=${COMMIT} -X main.BuildDate=${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}" -o /out/analyzer ./pkg/cmd/analyzer

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM ubuntu:24.04

# ARG scope is per-stage in Docker — re-declare it here so the LABEL below can
# reference the value passed via --build-arg VERSION=... instead of a literal
# that goes stale on custom builds.
ARG VERSION=1.0.0-beta.1

LABEL org.opencontainers.image.title="Mega-Analyzer" \
      org.opencontainers.image.description="Local APK/DEX/PE/ELF analysis platform" \
      org.opencontainers.image.licenses="BSD-3-Clause OR GPL-2.0-only" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/Promastergame/mega-analyzer"

# Runtime tooling for the optional dynamic-analysis features (adb / scrcpy).
# The analyzer core itself is 100% offline and needs none of this.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    android-sdk-platform-tools \
    adb \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user.
RUN useradd -m --non-unique -u 1000 analyzer && \
    mkdir -p /home/analyzer/workspace /home/analyzer/reports && \
    chown -R analyzer:analyzer /home/analyzer

COPY --from=builder /out/analyzer /usr/local/bin/analyzer

# Bundled rule sets and resources.
COPY configs/                    /home/analyzer/configs/
COPY pkg/internal/sastrules/     /home/analyzer/sastrules/
COPY pkg/internal/resources/     /home/analyzer/resources/
COPY LICENSE COPYING NOTICE.txt  /usr/share/doc/mega-analyzer/
COPY pkg/internal/apkloader/embedtools/PROVENANCE.json /usr/share/doc/mega-analyzer/BUNDLED_TOOLS.json
COPY third-party/licenses/       /usr/share/doc/mega-analyzer/licenses/

WORKDIR /home/analyzer
USER analyzer

VOLUME ["/home/analyzer/workspace", "/home/analyzer/reports"]

# Lightweight liveness probe against the default API mode below.
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=3 \
    CMD ["curl", "-f", "-s", "-o", "/dev/null", "http://127.0.0.1:5000/api/docs"]

# Default to the long-running REST server so `docker compose up` yields a
# working service instead of a --help print-and-exit loop. Override the
# command for one-shot CLI scans, e.g.:
#   docker run --rm -v "$PWD:/work" mega-analyzer -t /work/app.apk
ENTRYPOINT ["analyzer"]
CMD ["--api", "--api-port", "5000"]
