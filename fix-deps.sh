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

echo "Fixing package dependencies..."
sudo apt --fix-broken install -y

echo "Removing problematic CUDA packages..."
sudo apt-get remove -y libcudnn8-dev || true

echo "Cleaning package cache..."
sudo apt-get clean
sudo apt-get autoclean

echo "Updating package lists..."
sudo apt-get update

echo "Installing dependencies one by one..."
for pkg in build-essential libelf-dev clang-10 libbpf0 libbpf-dev linux-headers-generic; do
    echo "Installing $pkg..."
    sudo apt-get install -y $pkg || echo "Failed to install $pkg, continuing..."
done

echo "Setting up alternatives for clang..."
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-10 100

echo "Dependencies setup completed!"
echo "You can now try building the Docker image with:"
echo "docker build -t devshahriar/abproxy-agent:latest ." 