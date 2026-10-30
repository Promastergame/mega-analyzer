# sqli-login — intentionally vulnerable (CWE-89) local lab server.
# Local lab use only. Never deploy this image anywhere but 127.0.0.1.

FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/sqli-login .

FROM alpine:3.20
RUN adduser -D -H -u 10001 labuser
COPY --from=builder /out/sqli-login /usr/local/bin/sqli-login
USER labuser
ENV LISTEN_ADDR=127.0.0.1:18004
EXPOSE 18004
ENTRYPOINT ["/usr/local/bin/sqli-login"]
