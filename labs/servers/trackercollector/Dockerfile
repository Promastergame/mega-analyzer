# Local lab support service: the beacon sink the tracker servers phone home
# to. Not itself vulnerable — it just records the hits so the lab's tests
# and the ncer/mitm pipeline have something to observe. Local lab use only.

FROM golang:1.26-alpine AS builder
WORKDIR /src

COPY go.mod ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/trackercollector ./cmd

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/trackercollector /usr/local/bin/trackercollector

# Defaults to binding 127.0.0.1:18099 (see LISTEN_ADDR). The docker-compose
# service overrides LISTEN_ADDR to 0.0.0.0:18099 so it is reachable from the
# other lab containers on mega-analyzer-net, while the published host port
# stays bound to loopback:
#   ports:
#     - "127.0.0.1:18099:18099"
EXPOSE 18099

ENTRYPOINT ["/usr/local/bin/trackercollector"]
