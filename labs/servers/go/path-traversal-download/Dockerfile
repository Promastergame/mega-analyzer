# Intentionally vulnerable lab image (CWE-22: Path Traversal). Local lab
# use only. See README.md for the vulnerability write-up and exploit
# instructions.

FROM golang:1.26-alpine AS builder
WORKDIR /src

COPY go.mod ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/path-traversal-download .

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/path-traversal-download /usr/local/bin/path-traversal-download

# The server itself defaults to binding 127.0.0.1:18005 (see LISTEN_ADDR).
# When running via docker-compose, keep the published port bound to the
# loopback interface on the host too, e.g.:
#   ports:
#     - "127.0.0.1:18005:18005"
EXPOSE 18005

ENTRYPOINT ["/usr/local/bin/path-traversal-download"]
