FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/coin-lab .

FROM alpine:3.22

RUN addgroup -S lab && adduser -S -G lab lab && mkdir /data && chown lab:lab /data
COPY --from=build /out/coin-lab /usr/local/bin/coin-lab

USER lab
ENV LISTEN_ADDR=0.0.0.0:18011 \
    HTTP_LISTEN_ADDR=0.0.0.0:18111 \
    DB_PATH=/data/coin-lab.db
EXPOSE 18011 18111
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/coin-lab"]
