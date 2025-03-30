#!/bin/bash
set -e

# Configuration
IMAGE_NAME="docker.io/devshahriar/abproxy-agent:latest"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build_ebpf"

echo "Building abproxy-agent with real eBPF tracing functionality..."

# Install required dependencies
echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y \
    git build-essential pkg-config \
    libelf-dev clang llvm \
    libbpf-dev linux-headers-$(uname -r)

# Install Go if not already installed
if ! command -v go &> /dev/null; then
    echo "Installing Go..."
    curl -LO https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    rm go1.21.0.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
fi

# Create a clean build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cp -r . "$BUILD_DIR"
cd "$BUILD_DIR"

# Create comprehensive BPF program
cat > pkg/tracer/bpf/http_trace.c << 'EOF'
//+build ignore

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Maximum size for our data buffer
#define MAX_MSG_SIZE 256

// Event types
#define EVENT_TYPE_SSL_READ  1  // SSL_read event (responses)
#define EVENT_TYPE_SSL_WRITE 2  // SSL_write event (requests)

// Event structure
struct http_event {
    __u32 pid;          // Process ID
    __u32 tid;          // Thread ID
    __u64 timestamp;    // Event timestamp
    __u8 type;          // Event type (read/write)
    __u32 data_len;     // Length of the actual data
    __u32 conn_id;      // Connection ID to correlate request/response
    char data[MAX_MSG_SIZE]; // Actual HTTP data
} __attribute__((packed));

// Map to share events with userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

// Function signature for SSL_read
// int SSL_read(SSL *ssl, void *buf, int num);
SEC("uprobe/SSL_read")
int trace_ssl_read(struct pt_regs *ctx)
{
    // Get process info
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;
    
    // Prepare event
    struct http_event event = {0};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.type = EVENT_TYPE_SSL_READ;
    
    // Get SSL* from the 1st argument
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    
    // Get buffer pointer from the 2nd argument
    void *buf = (void *)PT_REGS_PARM2(ctx);
    
    // Get buffer length from the 3rd argument
    int len = (int)PT_REGS_PARM3(ctx);
    
    // Simple connection ID from SSL* pointer value
    event.conn_id = (__u32)((unsigned long)ssl);
    
    // Read return value after the function call completes
    // We'll use a kretprobe for this
    
    return 0;
}

SEC("uretprobe/SSL_read")
int trace_ssl_read_ret(struct pt_regs *ctx)
{
    // Get process info
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;
    
    // Get return value (actual bytes read)
    int ret = PT_REGS_RC(ctx);
    
    // Only process successful reads
    if (ret <= 0)
        return 0;
    
    // Limit to maximum data size
    if (ret > MAX_MSG_SIZE)
        ret = MAX_MSG_SIZE;
    
    // Prepare event
    struct http_event event = {0};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.type = EVENT_TYPE_SSL_READ;
    event.data_len = ret;
    
    // We don't have access to the buffer here
    // In a complete implementation, we would use a map to share context
    // between entry and return probes
    
    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// Function signature for SSL_write
// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe/SSL_write")
int trace_ssl_write(struct pt_regs *ctx)
{
    // Get process info
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;
    
    // Get SSL* from the 1st argument
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    
    // Get buffer pointer from the 2nd argument
    void *buf = (void *)PT_REGS_PARM2(ctx);
    
    // Get buffer length from the 3rd argument
    int len = (int)PT_REGS_PARM3(ctx);
    
    // Limit to maximum data size
    if (len > MAX_MSG_SIZE)
        len = MAX_MSG_SIZE;
    
    // Prepare event
    struct http_event event = {0};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.type = EVENT_TYPE_SSL_WRITE;
    event.data_len = len;
    event.conn_id = (__u32)((unsigned long)ssl);
    
    // Try to read from the buffer (may fail depending on security restrictions)
    if (buf && len > 0) {
        bpf_probe_read_user(event.data, len, buf);
    }
    
    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
EOF

# Create a tracer.go file that handles the eBPF events
cat > pkg/tracer/tracer.go << 'EOF'
package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/sirupsen/logrus"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf ./bpf/http_trace.c

// Event types
const (
	EventTypeSSLRead  = 1 // Response
	EventTypeSSLWrite = 2 // Request
)

// HTTPEvent represents a captured HTTP event
type HTTPEvent struct {
	PID       uint32
	TID       uint32
	Timestamp uint64
	Type      uint8
	DataLen   uint32
	ConnID    uint32 // Connection ID to correlate request/response
	Data      [256]byte

	// Parsed information (not part of the eBPF struct)
	ProcessName string
	Command     string
	Method      string
	URL         string
	StatusCode  int
	ContentType string
}

// Clone returns a copy of the HTTPEvent
func (e *HTTPEvent) Clone() *HTTPEvent {
	clone := *e // Shallow copy
	return &clone
}

// Tracer manages the eBPF program and event collection
type Tracer struct {
	objs          bpfObjects
	sslReadLink   link.Link
	sslWriteLink  link.Link
	sslReadReturn link.Link
	reader        *perf.Reader
	logger        *logrus.Logger
	eventCallback func(HTTPEvent)
	stopChan      chan struct{}
}

// NewTracer creates a new HTTP tracer
func NewTracer(logger *logrus.Logger, callback func(HTTPEvent)) (*Tracer, error) {
	t := &Tracer{
		logger:        logger,
		eventCallback: callback,
		stopChan:      make(chan struct{}),
	}

	// Load pre-compiled programs
	if err := loadBpfObjects(&t.objs, nil); err != nil {
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	// Create perf reader
	reader, err := perf.NewReader(t.objs.Events, 1024*4096)
	if err != nil {
		t.objs.Close()
		return nil, fmt.Errorf("creating perf reader: %w", err)
	}
	t.reader = reader

	return t, nil
}

// Start begins tracing HTTP traffic
func (t *Tracer) Start() error {
	if t.logger != nil {
		t.logger.Info("Starting HTTP tracer")
	}

	// Find OpenSSL library
	// This is where we'll attach our probes
	var libssl string
	for _, lib := range []string{
		"/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.1.1", 
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
	} {
		if _, err := ebpf.LoadPinnedMap(lib, nil); err == nil {
			libssl = lib
			break
		}
	}

	if libssl == "" {
		// If we can't find the library, we'll use a fake path for testing
		libssl = "/usr/lib/x86_64-linux-gnu/libssl.so.1.1"
		t.logger.Warn("Couldn't find OpenSSL library, using default path. Tracing may not work.")
	}

	// Attach to SSL_read function
	if t.logger != nil {
		t.logger.Infof("Attaching to SSL_read in %s", libssl)
	}
	
	var err error
	t.sslReadLink, err = link.Kprobe("SSL_read", t.objs.TraceSslRead, nil)
	if err != nil {
		t.reader.Close()
		t.objs.Close()
		return fmt.Errorf("attaching SSL_read uprobe: %w", err)
	}

	// Attach to SSL_read return
	t.sslReadReturn, err = link.Kretprobe("SSL_read", t.objs.TraceSslReadRet, nil)
	if err != nil {
		t.sslReadLink.Close()
		t.reader.Close()
		t.objs.Close()
		return fmt.Errorf("attaching SSL_read uretprobe: %w", err)
	}

	// Attach to SSL_write function
	if t.logger != nil {
		t.logger.Infof("Attaching to SSL_write in %s", libssl)
	}
	
	t.sslWriteLink, err = link.Kprobe("SSL_write", t.objs.TraceSslWrite, nil)
	if err != nil {
		t.sslReadReturn.Close()
		t.sslReadLink.Close()
		t.reader.Close()
		t.objs.Close()
		return fmt.Errorf("attaching SSL_write uprobe: %w", err)
	}

	// Start processing events
	go t.processEvents()

	return nil
}

// processEvents reads and processes events from the perf buffer
func (t *Tracer) processEvents() {
	var event HTTPEvent

	for {
		select {
		case <-t.stopChan:
			return
		default:
			record, err := t.reader.Read()
			if err != nil {
				if t.logger != nil {
					t.logger.Errorf("Reading perf events: %v", err)
				}
				continue
			}

			if record.LostSamples > 0 {
				if t.logger != nil {
					t.logger.Warnf("Lost %d samples", record.LostSamples)
				}
				continue
			}

			// Parse the event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				if t.logger != nil {
					t.logger.Errorf("Parsing event: %v", err)
				}
				continue
			}

			// Process the event
			t.processEvent(event)
		}
	}
}

// processEvent extracts HTTP information from the raw event
func (t *Tracer) processEvent(event HTTPEvent) {
	eventType := "unknown"
	if event.Type == EventTypeSSLRead {
		eventType = "response"
	} else if event.Type == EventTypeSSLWrite {
		eventType = "request"
	}

	// Get command and process name
	event.ProcessName = getProcessName(event.PID)
	event.Command = getCommand(event.PID)

	// Parse HTTP data if available
	if event.DataLen > 0 {
		data := event.Data[:event.DataLen]
		
		// Try to parse HTTP method, URL, status code, etc.
		if event.Type == EventTypeSSLWrite {
			// This is a request
			parts := bytes.SplitN(data, []byte(" "), 3)
			if len(parts) >= 2 {
				event.Method = string(parts[0])
				urlParts := bytes.SplitN(parts[1], []byte("?"), 2)
				event.URL = string(urlParts[0])
			}
			
			// Find Content-Type
			contentTypePos := bytes.Index(data, []byte("Content-Type: "))
			if contentTypePos > 0 {
				ctData := data[contentTypePos+14:]
				endPos := bytes.IndexByte(ctData, '\r')
				if endPos > 0 {
					event.ContentType = string(ctData[:endPos])
				}
			}
		} else if event.Type == EventTypeSSLRead {
			// This is a response
			parts := bytes.SplitN(data, []byte(" "), 3)
			if len(parts) >= 2 {
				statusCode := string(parts[1])
				event.StatusCode = 0
				fmt.Sscanf(statusCode, "%d", &event.StatusCode)
			}
			
			// Find Content-Type
			contentTypePos := bytes.Index(data, []byte("Content-Type: "))
			if contentTypePos > 0 {
				ctData := data[contentTypePos+14:]
				endPos := bytes.IndexByte(ctData, '\r')
				if endPos > 0 {
					event.ContentType = string(ctData[:endPos])
				}
			}
		}
	}

	if t.logger != nil && t.logger.IsLevelEnabled(logrus.DebugLevel) {
		t.logger.Debugf("HTTP %s from PID %d (%s): %s", 
			eventType, event.PID, event.ProcessName,
			formatEventSummary(event))
	}

	// Pass to callback
	if t.eventCallback != nil {
		t.eventCallback(event)
	}
}

// formatEventSummary provides a short summary of the event
func formatEventSummary(event HTTPEvent) string {
	if event.Type == EventTypeSSLWrite {
		return fmt.Sprintf("%s %s", event.Method, event.URL)
	} else {
		return fmt.Sprintf("Status: %d, Content-Type: %s", 
			event.StatusCode, event.ContentType)
	}
}

// getProcessName gets the process name for a PID
func getProcessName(pid uint32) string {
	// TODO: Implement proper process name lookup
	return fmt.Sprintf("process-%d", pid)
}

// getCommand gets the command line for a PID
func getCommand(pid uint32) string {
	// TODO: Implement proper command line lookup
	return fmt.Sprintf("command-%d", pid)
}

// Stop stops tracing HTTP traffic
func (t *Tracer) Stop() error {
	close(t.stopChan)
	return nil
}

// Close cleans up resources
func (t *Tracer) Close() error {
	if t.sslWriteLink != nil {
		t.sslWriteLink.Close()
	}
	
	if t.sslReadReturn != nil {
		t.sslReadReturn.Close()
	}
	
	if t.sslReadLink != nil {
		t.sslReadLink.Close()
	}
	
	if t.reader != nil {
		t.reader.Close()
	}
	
	t.objs.Close()
	return nil
}
EOF

# Create or update go.mod
go mod init abproxy 2>/dev/null || true
go mod edit -go=1.21
go get github.com/cilium/ebpf@v0.11.0
go get github.com/cilium/ebpf/link@v0.11.0
go get github.com/cilium/ebpf/perf@v0.11.0
go get github.com/sirupsen/logrus@v1.9.3
go get golang.org/x/sys@v0.15.0
go mod tidy

# Generate eBPF code
echo "Generating eBPF code..."
cd pkg/tracer
go generate
cd ../..

# Build the agent
echo "Building abproxy-agent binary..."
go build -o abproxy-agent ./cmd/agent

# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libelf1 \
    libbpf0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY abproxy-agent .

# Set capabilities to allow BPF operations
# This is required for eBPF programs to run
RUN apt-get update && \
    apt-get install -y --no-install-recommends libcap2-bin && \
    setcap cap_sys_admin,cap_bpf,cap_net_admin,cap_perfmon+eip /app/abproxy-agent && \
    apt-get remove -y libcap2-bin && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/app/abproxy-agent"]
EOF

# Build Docker image
echo "Building Docker image $IMAGE_NAME..."
docker build -t $IMAGE_NAME .

# Clean up build directory
cd ..
rm -rf "$BUILD_DIR"

echo "Image $IMAGE_NAME built successfully!"

# Update Kubernetes DaemonSet
echo "Updating Kubernetes DaemonSet with new image..."
if [ -f "deploy/kubernetes/daemonset.yaml" ]; then
    sed -i.bak "s|image: .*|image: $IMAGE_NAME|g" deploy/kubernetes/daemonset.yaml
    echo "Updated deploy/kubernetes/daemonset.yaml with the image reference."
fi

# Print instructions
echo ""
echo "=========================== INSTRUCTIONS ==================================="
echo "1. Push the image:"
echo "   docker push $IMAGE_NAME"
echo ""
echo "2. Deploy to Kubernetes:"
echo "   kubectl apply -f deploy/kubernetes/daemonset.yaml"
echo ""
echo "3. To see the logs:"
echo "   kubectl logs -n default -l app=abproxy-agent"
echo ""
echo "4. To troubleshoot, exec into a pod:"
echo "   kubectl exec -it \$(kubectl get pods -l app=abproxy-agent -o name | head -1) -- /bin/bash"
echo "=========================================================================="
echo "" 