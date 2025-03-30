#!/bin/bash
set -e

echo "Cleaning up problematic repositories..."
sudo rm -f /etc/apt/sources.list.d/cuda*
sudo rm -f /etc/apt/sources.list.d/nvidia*

echo "Updating package lists..."
sudo apt-get update

echo "Installing required dependencies..."
sudo apt-get install -y \
    build-essential \
    clang \
    libbpf-dev \
    linux-headers-$(uname -r)

echo "Dependencies installed successfully!"
echo "You can now build the Docker image with:"
echo "docker build -t devshahriar/abproxy-agent:latest ." 