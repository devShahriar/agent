FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum if they exist
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build with explicit architecture setting
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /go/bin/test-server ./cmd/test-server

# Final stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates

COPY --from=builder /go/bin/test-server /usr/local/bin/test-server

EXPOSE 8080

ENTRYPOINT ["test-server"] 