#!/bin/bash

# Install bpftool if not present
if ! command -v bpftool &> /dev/null; then
    apt-get update
    apt-get install -y linux-tools-common linux-tools-generic
fi

# Generate vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > pkg/tracer/bpf/vmlinux.h 