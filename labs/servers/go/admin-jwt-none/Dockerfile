# admin-jwt-none — INTENTIONALLY VULNERABLE lab server (CWE-347).
# Local lab use only. See README.md before running this anywhere.

FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/admin-jwt-none .

FROM alpine:3.20
RUN adduser -D -H -u 10001 labuser
COPY --from=builder /out/admin-jwt-none /usr/local/bin/admin-jwt-none
USER labuser
ENV LISTEN_ADDR=127.0.0.1:18002
EXPOSE 18002
ENTRYPOINT ["/usr/local/bin/admin-jwt-none"]
