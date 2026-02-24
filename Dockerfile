# Build stage
FROM golang:1.25-alpine AS builder

ARG VERSION=dev

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy only source code (no tests, docs, etc.)
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY pkg/ ./pkg/

# Build binaries
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.Version=${VERSION}" -o /bin/api-gateway ./cmd/api-gateway
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.Version=${VERSION}" -o /bin/sovra ./cmd/sovra-cli

# Runtime stage - minimal image
FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 sovra && \
    adduser -u 1000 -G sovra -s /bin/sh -D sovra

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /bin/api-gateway /app/
COPY --from=builder /bin/sovra /app/

USER sovra

# Default to api-gateway, can be overridden
ENTRYPOINT ["/app/api-gateway"]
