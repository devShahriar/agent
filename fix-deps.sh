#!/bin/bash
set -e

echo "Disabling problematic NVIDIA repositories..."
sudo mv /etc/apt/sources.list.d/cuda* /tmp/ 2>/dev/null || true
sudo mv /etc/apt/sources.list.d/nvidia* /tmp/ 2>/dev/null || true

# Create a temporary sources list with just what we need
echo "Setting up clean package sources..."
echo "deb http://archive.ubuntu.com/ubuntu focal main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu focal-updates main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu focal-security main restricted universe multiverse" | sudo tee /etc/apt/sources.list.d/ubuntu-clean.list

# Temporarily disable kernel module updates
echo "Temporarily disabling automatic kernel updates..."
sudo mkdir -p /etc/dpkg/dpkg.cfg.d/
echo 'path-exclude=/lib/modules/*' | sudo tee /etc/dpkg/dpkg.cfg.d/exclude-modules
echo 'path-exclude=/boot/*' | sudo tee -a /etc/dpkg/dpkg.cfg.d/exclude-modules

echo "Removing CUDA packages (without kernel updates)..."
DEBIAN_FRONTEND=noninteractive sudo apt-get remove -y libcudnn8 libcudnn8-dev || true

echo "Cleaning package cache..."
sudo apt-get clean
sudo apt-get autoclean

echo "Updating package lists..."
sudo apt-get update

echo "Installing minimal dependencies..."
DEBIAN_FRONTEND=noninteractive sudo apt-get install -y --no-install-recommends \
    build-essential \
    clang-10 \
    libelf-dev \
    libbpf0 \
    libbpf-dev

echo "Setting up alternatives for clang..."
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-10 100 || true

# Re-enable kernel module updates
echo "Re-enabling kernel module updates..."
sudo rm -f /etc/dpkg/dpkg.cfg.d/exclude-modules

echo "Dependencies setup completed!"
echo "You can now try building the Docker image with:"
echo "docker build -t devshahriar/abproxy-agent:latest ." 