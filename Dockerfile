# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the relay node
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o rerc-node ./cmd/node

# Build the client
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o rerc-client ./cmd/client

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN adduser -D -s /bin/sh rerc

# Set working directory
WORKDIR /home/rerc

# Copy binaries from builder
COPY --from=builder /app/rerc-node .
COPY --from=builder /app/rerc-client .

# Change ownership
RUN chown -R rerc:rerc /home/rerc

# Switch to non-root user
USER rerc

# Expose default port
EXPOSE 8080

# Default command (relay node)
CMD ["./rerc-node", "-addr", ":8080"]
