#!/bin/bash

# Make script executable
chmod +x dev.sh

case "$1" in
  "up")
    docker-compose up -d
    ;;
  "down")
    docker-compose down
    ;;
  "shell")
    docker-compose exec dev /bin/bash
    ;;
  "build")
    docker-compose exec dev go build -o abproxy-agent ./cmd/agent
    ;;
  "run")
    docker-compose exec dev ./abproxy-agent
    ;;
  "generate")
    docker-compose exec dev bash -c "cd pkg/tracer && go generate"
    ;;
  "test")
    docker-compose exec dev go test ./...
    ;;
  *)
    echo "Usage: $0 {up|down|shell|build|run|generate|test}"
    echo "  up        - Start development container"
    echo "  down      - Stop development container"
    echo "  shell     - Open shell in development container"
    echo "  build     - Build the agent"
    echo "  run       - Run the agent"
    echo "  generate  - Generate eBPF code"
    echo "  test      - Run tests"
    exit 1
    ;;
esac 