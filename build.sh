#!/bin/bash

set -e

echo "Building ABproxy HTTP Traffic Tracing Agent..."

# Ensure the script is run as root for eBPF capabilities
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo) for eBPF capabilities"
  exit 1
fi

# Check if we're inside the container
if [ -f "/.dockerenv" ]; then
  INSIDE_CONTAINER=true
else
  INSIDE_CONTAINER=false
fi

# If outside container and docker is available, prefer that
if [ "$INSIDE_CONTAINER" = false ] && command -v docker >/dev/null 2>&1; then
  echo "Using Docker environment..."
  
  # Build the container if it doesn't exist or needs updating
  docker compose build
  
  # Generate eBPF code in the container
  docker compose exec -T dev bash -c "cd /app && go generate ./pkg/tracer"
  
  # Build the agent in the container
  docker compose exec -T dev bash -c "cd /app && go build -o abproxy-agent ./cmd/agent"
  
  echo "Build completed successfully. Run with: sudo ./abproxy-agent"
else
  # Direct build within container or local system
  echo "Building directly..."
  
  # Ensure dependencies are installed
  if [ "$INSIDE_CONTAINER" = false ]; then
    if command -v apt-get >/dev/null 2>&1; then
      echo "Installing dependencies..."
      apt-get update
      apt-get install -y clang llvm libelf-dev
    fi
  fi
  
  # Generate eBPF code
  echo "Generating eBPF code..."
  go generate ./pkg/tracer
  
  # Build the agent
  echo "Building agent binary..."
  go build -o abproxy-agent ./cmd/agent
  
  echo "Build completed successfully. Run with: sudo ./abproxy-agent"
fi 