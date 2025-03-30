FROM ubuntu:22.04

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Update and install required packages
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    apt-utils \
    ca-certificates \
    curl \
    git \
    ssh \
    gnupg2 \
    sudo \
    vim \
    wget \
    build-essential \
    llvm \
    clang \
    libelf-dev \
    pkg-config \
    golang-go \
    linux-headers-generic \
    linux-tools-generic \
    bpftool \
    && rm -rf /var/lib/apt/lists/*

# Add go to PATH
ENV PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin

# Install Go 1.21
RUN wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz && \
    rm go1.21.0.linux-amd64.tar.gz

# Create non-root user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# Install Go tools
RUN go install github.com/cilium/ebpf/cmd/bpf2go@v0.11.0

# Copy bpf kernel headers for BTF support
RUN mkdir -p /usr/include/bpf

WORKDIR /workspace

# Switch to non-root user
USER $USERNAME 