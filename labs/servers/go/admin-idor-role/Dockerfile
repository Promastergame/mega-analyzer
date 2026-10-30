# labs-admin-idor-role — intentionally vulnerable (CWE-639) local lab server.
# Local security-training use only. Never deploy this image anywhere
# reachable outside 127.0.0.1 of the lab host.

FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/admin-idor-role .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/admin-idor-role /usr/local/bin/admin-idor-role
ENV LISTEN_ADDR=127.0.0.1:18003
EXPOSE 18003
ENTRYPOINT ["/usr/local/bin/admin-idor-role"]
