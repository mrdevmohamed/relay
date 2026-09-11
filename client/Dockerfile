# syntax=docker/dockerfile:1
# Multi-stage build for the local relay client. Runs as non-root.

FROM golang:1.24-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/relay-client ./cmd/relay-client

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /out/relay-client /app/relay-client
COPY configs/client.example.yaml /app/configs/client.example.yaml
# HTTP CONNECT proxy, SOCKS5 proxy, management (/health, /metrics).
EXPOSE 8080 1080 9090
USER nonroot:nonroot
ENTRYPOINT ["/app/relay-client"]
CMD ["--config", "/app/configs/client.yaml"]
