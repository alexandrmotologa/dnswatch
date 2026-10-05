# Build stage for Go binary
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Install ca-certificates and git
RUN apk add --no-cache ca-certificates git tzdata

# Copy dependency definitions
COPY go.mod go.sum ./
RUN go mod download

# Copy source tree (including pre-built pkg/server/dist assets)
COPY . .

# Build static binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -extldflags '-static'" \
    -trimpath \
    -o /build/dnswatch \
    ./cmd/dnswatch

# Final minimal production stage (<15MB)
FROM alpine:3.21

# Add CA certificates for secure TLS DoH connections
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 10001 dnswatch

USER dnswatch

WORKDIR /home/dnswatch

COPY --from=builder /build/dnswatch /usr/local/bin/dnswatch

# Default Web Studio port
EXPOSE 8080

ENTRYPOINT ["dnswatch"]
CMD ["serve", "--port=8080", "--host=0.0.0.0"]
