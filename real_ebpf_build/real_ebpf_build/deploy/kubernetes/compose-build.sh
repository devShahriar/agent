#!/bin/bash
set -e

# Configuration
IMAGE_NAME="docker.io/devshahriar/abproxy-agent:latest"

echo "Building abproxy-agent image for Kubernetes using Docker Compose..."

# Make sure the dev environment is up
docker-compose up -d

# Install dependencies in the container
echo "Setting up build environment in container..."
docker-compose exec -T dev bash -c "cd /app && \
apt-get update && \
apt-get install -y wget build-essential clang llvm libelf-dev && \
if ! command -v go &> /dev/null; then \
  echo 'Installing Go...' && \
  wget -q https://dl.google.com/go/go1.21.0.linux-amd64.tar.gz && \
  tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz && \
  rm go1.21.0.linux-amd64.tar.gz; \
fi"

# Build the agent
echo "Building agent inside container..."
docker-compose exec -T dev bash -c "cd /app && PATH=/usr/local/go/bin:\$PATH go generate ./pkg/tracer && PATH=/usr/local/go/bin:\$PATH go build -o abproxy-agent ./cmd/agent"

# Create a new Docker image from the built binary
echo "Creating Docker image from the built binary..."
cat > Dockerfile.prod << EOF
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
    ca-certificates \\
    libelf1 \\
    libbpf0 \\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY abproxy-agent .

ENTRYPOINT ["/app/abproxy-agent"]
EOF

# Copy the binary from the dev container
docker cp $(docker-compose ps -q dev):/app/abproxy-agent ./abproxy-agent

# Build the production image
docker build -t $IMAGE_NAME -f Dockerfile.prod .

# Clean up temporary files
rm -f Dockerfile.prod abproxy-agent

echo "Image built successfully: $IMAGE_NAME"

# Ask for confirmation before pushing
read -p "Push image to $IMAGE_NAME? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Logging in to Docker Hub..."
    docker login
    
    echo "Pushing image to Docker Hub..."
    docker push $IMAGE_NAME
    
    echo "Image pushed successfully!"
    
    # Update daemonset file with the image
    sed -i.bak "s|image: .*|image: $IMAGE_NAME|g" deploy/kubernetes/daemonset.yaml
    echo "Updated deploy/kubernetes/daemonset.yaml with the image reference."
fi

echo "Done!" 