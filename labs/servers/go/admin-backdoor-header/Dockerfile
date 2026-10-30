# Intentionally vulnerable lab image (CWE-798). Local lab use only.
# See README.md for the vulnerability write-up and exploit instructions.

FROM golang:1.26-alpine AS builder
WORKDIR /src

COPY go.mod ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/admin-backdoor-header .

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/admin-backdoor-header /usr/local/bin/admin-backdoor-header

# The server itself defaults to binding 127.0.0.1:18001 (see LISTEN_ADDR).
# When running via docker-compose, keep the published port bound to the
# loopback interface on the host too, e.g.:
#   ports:
#     - "127.0.0.1:18001:18001"
EXPOSE 18001

ENTRYPOINT ["/usr/local/bin/admin-backdoor-header"]
