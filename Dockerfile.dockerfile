# Dockerfile

FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install git and dependencies
RUN apk add --no-cache git gcc musl-dev

# Copy source code files
COPY *.go ./
COPY go.mod ./

# Initialize module and get dependencies explicitly
RUN go mod tidy
RUN go mod download
RUN go get github.com/miekg/dns@v1.1.58

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o dns-redirector

# Create a minimal runtime image
FROM alpine:3.18

WORKDIR /app

# Install certificates for HTTPS requests if needed
RUN apk add --no-cache ca-certificates

# Copy the binary from the builder stage
COPY --from=builder /build/dns-redirector /app/

# Create necessary directories
RUN mkdir -p /app/data

# Copy configuration files
COPY ip_blocks.txt /app/ip_blocks.txt
COPY config.txt /app/config.txt

# Set up entrypoint script
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

# Health check to verify DNS server is running
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD nc -uz 127.0.0.1 53 || exit 1

# Expose DNS port
EXPOSE 53/udp

# Set signal handling mode to ensure proper shutdown
STOPSIGNAL SIGTERM

ENTRYPOINT ["/app/entrypoint.sh"]
