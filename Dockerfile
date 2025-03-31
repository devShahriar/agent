FROM --platform=linux/amd64 golang:1.21-alpine AS builder

WORKDIR /app
COPY . .

# Install basic build tools
RUN apk add --no-cache gcc musl-dev

# Build the agent
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o abproxy-agent ./cmd/agent

# Final stage
FROM --platform=linux/amd64 alpine:latest

WORKDIR /app
COPY --from=builder /app/abproxy-agent .

# Install SSL library for runtime
RUN apk add --no-cache libssl3

# Create BPF filesystem directory
RUN mkdir -p /sys/fs/bpf/abproxy

CMD ["./abproxy-agent"] 