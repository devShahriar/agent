#!/bin/bash

set -e

echo "Building ABProxy Agent..."

# Check if we're on Linux or macOS
if [ "$(uname -s)" == "Darwin" ]; then
    echo "Building on macOS (Note: BPF tracing will be limited)"
    go build -o bin/abproxy-agent ./cmd/agent
else
    echo "Building on Linux with BPF support"
    
    # Install dependencies if needed
    if ! which clang > /dev/null; then
        echo "Installing clang..."
        apt-get update && apt-get install -y clang llvm libelf-dev
    fi
    
    # Generate BPF code
    echo "Generating BPF code..."
    cd pkg/tracer
    go generate
    cd ../..
    
    # Build the agent
    echo "Building agent binary..."
    CGO_ENABLED=1 go build -o bin/abproxy-agent ./cmd/agent
fi

echo "Build completed successfully!" 