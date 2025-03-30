.PHONY: build clean run

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=abproxy-agent

# Build the eBPF program and Go binary
build: generate
	$(GOBUILD) -o $(BINARY_NAME) ./cmd/agent

# Generate Go code from eBPF program
generate:
	$(GOCMD) generate ./pkg/tracer

# Clean build files
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f pkg/tracer/http_trace_bpf*

# Download dependencies
deps:
	$(GOMOD) download

# Run the agent (requires root privileges)
run: build
	sudo ./$(BINARY_NAME)

# Install required tools
tools:
	$(GOGET) github.com/cilium/ebpf/cmd/bpf2go@latest 