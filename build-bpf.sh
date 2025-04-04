#!/bin/bash
set -e

# Build the Docker image
echo "Building Docker image for BPF compilation..."
docker build -t abproxy-bpf-builder -f Dockerfile.bpf .

# Run the Docker container to generate the BPF code
echo "Generating BPF code..."
docker run --rm -v $(pwd):/app abproxy-bpf-builder

echo "BPF code generation complete!" 