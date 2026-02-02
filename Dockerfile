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

# Build all binaries
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.Version=${VERSION}" -o /bin/api-gateway ./cmd/api-gateway
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.Version=${VERSION}" -o /bin/audit-service ./cmd/audit-service
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.Version=${VERSION}" -o /bin/federation-manager ./cmd/federation-manager
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.Version=${VERSION}" -o /bin/key-lifecycle ./cmd/key-lifecycle
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.Version=${VERSION}" -o /bin/policy-engine ./cmd/policy-engine
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.Version=${VERSION}" -o /bin/sovra-cli ./cmd/sovra-cli

# Runtime stage - minimal image
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 sovra && \
    adduser -u 1000 -G sovra -s /bin/sh -D sovra

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /bin/api-gateway /app/
COPY --from=builder /bin/audit-service /app/
COPY --from=builder /bin/federation-manager /app/
COPY --from=builder /bin/key-lifecycle /app/
COPY --from=builder /bin/policy-engine /app/
COPY --from=builder /bin/sovra-cli /app/

USER sovra

# Default to api-gateway, can be overridden
ENTRYPOINT ["/app/api-gateway"]
