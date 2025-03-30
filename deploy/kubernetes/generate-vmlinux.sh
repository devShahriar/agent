#!/bin/bash

# Check if bpftool is installed
if ! command -v bpftool &> /dev/null; then
    echo "bpftool not found. Installing..."
    apt-get update
    apt-get install -y linux-tools-common linux-tools-generic
fi

# Generate vmlinux.h from BTF
bpftool btf dump file /sys/kernel/btf/vmlinux format c > pkg/tracer/bpf/vmlinux.h 