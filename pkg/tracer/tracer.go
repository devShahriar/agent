package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/sirupsen/logrus"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86 -D__KERNEL__ -D__BPF_TRACING__ -DBPF_NO_PRESERVE_ACCESS_INDEX -DHAVE_NO_VDSO -DNO_CORE_RELOC -DCORE_DISABLE_VDSO_LOOKUP -DSKIP_KERNEL_VERSION=1 -DBPF_NO_PRESERVE_ACCESS_INDEX=1 -D__BPF_TRACING__ -D__BPF_CORE_READ__ -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -I/usr/include" -no-strip -target bpfel bpf ./bpf/http_trace.c

// Event types
const (
	EventTypeSSLRead     = 1 // Response
	EventTypeSSLWrite    = 2 // Request
	EventTypeSocketRead  = 3 // Response
	EventTypeSocketWrite = 4 // Request
)

// ProcessInfo represents process information
type ProcessInfo struct {
	PID  uint32
	PPID uint32
	Comm string
}

// HTTPEvent represents a captured HTTP event
type HTTPEvent struct {
	Type        uint8
	PID         uint32
	TID         uint32
	Timestamp   uint64
	ConnID      uint32
	DataLen     uint32
	Data        [256]byte
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

// Storage interface for storing HTTP events
type Storage interface {
	Store(event HTTPEvent) error
	Close() error
}

// FileStorage implements Storage interface for file-based storage
type FileStorage struct {
	dir    string
	logger *logrus.Logger
	mu     sync.Mutex
}

// NewFileStorage creates a new file-based storage
func NewFileStorage(dir string) (Storage, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	return &FileStorage{
		dir:    dir,
		logger: logrus.New(),
	}, nil
}

// Store implements Storage interface
func (s *FileStorage) Store(event HTTPEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create a filename based on timestamp and PID
	filename := fmt.Sprintf("%s/http_%d_%d.json", s.dir, event.PID, event.Timestamp)

	// Create the document
	doc := map[string]interface{}{
		"timestamp":    time.Unix(0, int64(event.Timestamp)),
		"type":         event.Type,
		"pid":          event.PID,
		"tid":          event.TID,
		"process_name": event.ProcessName,
		"command":      event.Command,
		"method":       event.Method,
		"url":          event.URL,
		"status_code":  event.StatusCode,
		"content_type": event.ContentType,
		"data_len":     event.DataLen,
		"data":         string(event.Data[:event.DataLen]),
	}

	// Marshal the document to JSON
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}

	// Write the file
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	s.logger.WithField("filename", filename).Debug("Stored HTTP event")
	return nil
}

// Close implements Storage interface
func (s *FileStorage) Close() error {
	return nil
}

// ElasticsearchStorage implements Storage interface for Elasticsearch-based storage
type ElasticsearchStorage struct {
	url    string
	index  string
	client *elasticsearch.Client
	logger *logrus.Logger
}

// NewElasticsearchStorage creates a new Elasticsearch-based storage
func NewElasticsearchStorage(url, index string) (Storage, error) {
	// Configure the client
	cfg := elasticsearch.Config{
		Addresses: []string{url},
		// Add authentication if needed
		// Username: "elastic",
		// Password: "changeme",
	}

	// Create the client
	client, err := elasticsearch.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Elasticsearch client: %w", err)
	}

	// Check if the client is working
	info, err := client.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get Elasticsearch info: %w", err)
	}
	defer info.Body.Close()

	if info.IsError() {
		return nil, fmt.Errorf("Elasticsearch info error: %s", info.String())
	}

	return &ElasticsearchStorage{
		url:    url,
		index:  index,
		client: client,
		logger: logrus.New(),
	}, nil
}

// Store implements Storage interface
func (s *ElasticsearchStorage) Store(event HTTPEvent) error {
	// Create the document
	doc := map[string]interface{}{
		"timestamp":    time.Unix(0, int64(event.Timestamp)),
		"type":         event.Type,
		"pid":          event.PID,
		"tid":          event.TID,
		"process_name": event.ProcessName,
		"command":      event.Command,
		"method":       event.Method,
		"url":          event.URL,
		"status_code":  event.StatusCode,
		"content_type": event.ContentType,
		"data_len":     event.DataLen,
		"data":         string(event.Data[:event.DataLen]),
	}

	// Marshal the document to JSON
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}

	// Create the index request
	req := esapi.IndexRequest{
		Index:      s.index,
		DocumentID: fmt.Sprintf("%d-%d-%d", event.PID, event.TID, event.Timestamp),
		Body:       bytes.NewReader(data),
		Refresh:    "true",
	}

	// Perform the request
	res, err := req.Do(context.Background(), s.client)
	if err != nil {
		return fmt.Errorf("failed to index document: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error indexing document: %s", res.String())
	}

	return nil
}

// Close implements Storage interface
func (s *ElasticsearchStorage) Close() error {
	// The Elasticsearch client doesn't need explicit closing
	return nil
}

// Tracer represents an HTTP traffic tracer
type Tracer struct {
	objs          *bpfObjects
	perfReader    *perf.Reader
	logger        *logrus.Logger
	storage       Storage
	eventCallback func(HTTPEvent)
	stopChan      chan struct{}
	uprobes       []link.Link

	// Connection context to correlate requests and responses
	connMu      sync.RWMutex
	connections map[uint32]*HTTPEvent

	// Process info cache to avoid repeated lookups
	procMu    sync.RWMutex
	procCache map[uint32]processInfo
}

type processInfo struct {
	name    string
	command string
}

// findSSLPath attempts to find the SSL library path
func findSSLPath() (string, error) {
	// For Linux hosts, add more potential paths
	paths := []string{
		// Standard Linux paths
		"/usr/lib/libssl.so.3",
		"/usr/lib/libssl.so.1.1",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		// For Debian/Ubuntu
		"/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/lib/x86_64-linux-gnu/libssl.so.3",
		// For CentOS/RHEL
		"/lib64/libssl.so.1.1",
		"/lib64/libssl.so.3",
		// For Alpine
		"/lib/libssl.so.1.1",
		"/lib/libssl.so.3",
		// ARM paths
		"/usr/lib/aarch64-linux-gnu/libssl.so.3",
		"/usr/lib/aarch64-linux-gnu/libssl.so.1.1",
		"/lib/aarch64-linux-gnu/libssl.so.1.1",
		// Additional paths for container environments
		"/usr/local/lib/libssl.so.3",
		"/usr/local/lib/libssl.so.1.1",
		"/opt/lib/libssl.so.3",
		"/opt/lib/libssl.so.1.1",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("could not find libssl.so")
}

// NewTracer creates a new HTTP tracer
func NewTracer(
	logger *logrus.Logger,
	storage Storage,
	callback func(HTTPEvent),
) (*Tracer, error) {
	t := &Tracer{
		logger:        logger,
		storage:       storage,
		eventCallback: callback,
		stopChan:      make(chan struct{}),
		uprobes:       make([]link.Link, 0),
		connections:   make(map[uint32]*HTTPEvent),
		procCache:     make(map[uint32]processInfo),
	}

	// Set environment variables for better BPF compatibility
	os.Setenv("LIBEBPF_IGNORE_VDSO_ERR", "1")
	os.Setenv("BPF_FORCE_KERNEL_VERSION", "0")

	// For Linux Minikube, ensure BPF filesystem is mounted
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		if logger != nil {
			logger.Warn("BPF filesystem not found at /sys/fs/bpf, attempting to create")
		}
		// Try to mount BPF filesystem if it doesn't exist
		if err := os.MkdirAll("/sys/fs/bpf", 0755); err != nil {
			logger.WithError(err).
				Info("Failed to create BPF directory, continuing anyway")
		}
	}

	// Create application directory in BPF filesystem
	bpfDir := "/sys/fs/bpf/abproxy"
	if err := os.MkdirAll(bpfDir, 0700); err != nil {
		if logger != nil {
			logger.WithError(err).
				Info("Failed to create BPF subdirectory, continuing anyway")
		}
	}

	// Clean up any existing pinned maps
	cleanupPinnedMaps(bpfDir)

	// Load pre-compiled programs with modified options
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 1,
			LogSize:  65535,
		},
		Maps: ebpf.MapOptions{
			PinPath: bpfDir,
		},
	}

	// Load BPF objects
	objs := bpfObjects{}
	err := loadBpfObjects(&objs, opts)
	if err != nil {
		if strings.Contains(err.Error(), "vdso") {
			// vDSO errors can be ignored in containerized environments
			if logger != nil {
				logger.WithError(err).
					Warn("vDSO lookup failed (expected in containers), continuing")
			}
		} else {
			// Other errors are more serious but might not be fatal
			if logger != nil {
				logger.WithError(err).Error("Failed to load BPF objects")
			}
			return nil, fmt.Errorf("loading BPF objects: %w", err)
		}
	}

	t.objs = &objs

	// Initialize perf reader for the events map
	if t.objs.Events != nil {
		rd, err := perf.NewReader(t.objs.Events, os.Getpagesize()*16)
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("creating perf reader: %w", err)
		}
		t.perfReader = rd
	} else if logger != nil {
		logger.Warn("Events map is nil, perf reader not initialized")
	}

	return t, nil
}

// cleanupPinnedMaps removes any existing pinned maps
func cleanupPinnedMaps(bpfDir string) {
	// List of maps to clean up
	maps := []string{
		"events",
		"conn_state",
		"process_info",
		"active_fds",
		"active_sockets",
		"socket_info",
		"event_storage",
		"read_args_map",
	}

	for _, mapName := range maps {
		mapPath := filepath.Join(bpfDir, mapName)
		if err := os.Remove(mapPath); err != nil && !os.IsNotExist(err) {
			logrus.WithError(err).WithField("map", mapName).
				Warn("Failed to remove pinned map")
		}
	}
}

// LoadSSLPrograms loads SSL tracing programs without using vDSO
func loadSSLPrograms() (*ebpf.Program, *ebpf.Program, error) {
	// Try to load from the current directory first
	spec, err := ebpf.LoadCollectionSpec("bpf_bpfel.o")
	if err != nil {
		// Try alternative paths
		paths := []string{
			"/app/pkg/tracer/bpf_bpfel.o",
			"./pkg/tracer/bpf_bpfel.o",
			"bpf_bpfel.o",
		}
		for _, path := range paths {
			spec, err = ebpf.LoadCollectionSpec(path)
			if err == nil {
				break
			}
		}
		if err != nil {
			return nil, nil, fmt.Errorf("loading BPF spec: %w", err)
		}
	}

	// Set up map options for pinning
	bpfDir := "/sys/fs/bpf/abproxy"
	if err := os.MkdirAll(bpfDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("creating BPF directory: %w", err)
	}

	// Load the collection with pinning options
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: bpfDir,
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("creating BPF collection: %w", err)
	}
	defer coll.Close()

	// Get the individual programs
	readProg := coll.DetachProgram("trace_ssl_read")
	if readProg == nil {
		return nil, nil, fmt.Errorf("program trace_ssl_read not found")
	}

	writeProg := coll.DetachProgram("trace_ssl_write")
	if writeProg == nil {
		readProg.Close()
		return nil, nil, fmt.Errorf("program trace_ssl_write not found")
	}

	return readProg, writeProg, nil
}

// Start begins tracing HTTP traffic
func (t *Tracer) Start() error {
	t.logger.Info("Starting HTTP traffic tracer...")

	// Find SSL library
	sslPath, err := findSSLPath()
	if err != nil {
		t.logger.WithError(err).
			Warn("Could not find SSL library, will only trace socket operations")
	} else {
		t.logger.WithField("ssl_path", sslPath).Info("Found SSL library")

		// Open the SSL library
		ex, err := link.OpenExecutable(sslPath)
		if err != nil {
			t.logger.WithError(err).Warn("Could not open SSL library, will only trace socket operations")
		} else {
			// Load SSL programs manually to avoid vDSO issues
			readProg, writeProg, err := loadSSLPrograms()
			if err != nil {
				t.logger.WithError(err).Warn("Manual program loading failed, falling back to preloaded programs")
			} else {
				// Attach to SSL_read
				readUprobe, err := ex.Uprobe("SSL_read", readProg, nil)
				if err != nil {
					t.logger.WithError(err).Error("Failed to attach SSL_read uprobe")
				} else {
					t.uprobes = append(t.uprobes, readUprobe)
					t.logger.Info("Successfully attached SSL_read uprobe")
				}

				// Attach to SSL_write
				writeUprobe, err := ex.Uprobe("SSL_write", writeProg, nil)
				if err != nil {
					t.logger.WithError(err).Error("Failed to attach SSL_write uprobe")
				} else {
					t.uprobes = append(t.uprobes, writeUprobe)
					t.logger.Info("Successfully attached SSL_write uprobe")
				}
			}
		}
	}

	// Attach syscall tracepoints
	if t.objs != nil {
		// Attach accept4 tracepoints
		tp, err := link.Tracepoint(
			"syscalls",
			"sys_enter_accept4",
			t.objs.TraceAccept4,
			nil,
		)
		if err != nil {
			t.logger.WithError(err).Error("Failed to attach sys_enter_accept4 tracepoint")
		} else {
			t.uprobes = append(t.uprobes, tp)
			t.logger.Info("Successfully attached sys_enter_accept4 tracepoint")
		}

		tp, err = link.Tracepoint(
			"syscalls",
			"sys_exit_accept4",
			t.objs.TraceAccept4Exit,
			nil,
		)
		if err != nil {
			t.logger.WithError(err).Error("Failed to attach sys_exit_accept4 tracepoint")
		} else {
			t.uprobes = append(t.uprobes, tp)
			t.logger.Info("Successfully attached sys_exit_accept4 tracepoint")
		}

		// Attach connect tracepoint
		tp, err = link.Tracepoint(
			"syscalls",
			"sys_enter_connect",
			t.objs.TraceConnect,
			nil,
		)
		if err != nil {
			t.logger.WithError(err).Error("Failed to attach sys_enter_connect tracepoint")
		} else {
			t.uprobes = append(t.uprobes, tp)
			t.logger.Info("Successfully attached sys_enter_connect tracepoint")
		}

		// Attach write tracepoint
		tp, err = link.Tracepoint("syscalls", "sys_enter_write", t.objs.TraceWrite, nil)
		if err != nil {
			t.logger.WithError(err).Error("Failed to attach sys_enter_write tracepoint")
		} else {
			t.uprobes = append(t.uprobes, tp)
			t.logger.Info("Successfully attached sys_enter_write tracepoint")
		}

		// Attach read tracepoints
		tp, err = link.Tracepoint("syscalls", "sys_enter_read", t.objs.TraceRead, nil)
		if err != nil {
			t.logger.WithError(err).Error("Failed to attach sys_enter_read tracepoint")
		} else {
			t.uprobes = append(t.uprobes, tp)
			t.logger.Info("Successfully attached sys_enter_read tracepoint")
		}

		tp, err = link.Tracepoint("syscalls", "sys_exit_read", t.objs.TraceReadRet, nil)
		if err != nil {
			t.logger.WithError(err).Error("Failed to attach sys_exit_read tracepoint")
		} else {
			t.uprobes = append(t.uprobes, tp)
			t.logger.Info("Successfully attached sys_exit_read tracepoint")
		}

		// Attach close tracepoint
		tp, err = link.Tracepoint("syscalls", "sys_enter_close", t.objs.TraceClose, nil)
		if err != nil {
			t.logger.WithError(err).Error("Failed to attach sys_enter_close tracepoint")
		} else {
			t.uprobes = append(t.uprobes, tp)
			t.logger.Info("Successfully attached sys_enter_close tracepoint")
		}
	} else {
		t.logger.Error("BPF objects not loaded, cannot attach tracepoints")
	}

	// Start polling for events
	go t.pollEvents()

	t.logger.Info("HTTP traffic tracer started successfully")
	t.logger.Info("Tracer is running. Press Ctrl+C to stop.")

	return nil
}

// getProcessInfo retrieves the process name and command for a PID
func (t *Tracer) getProcessInfo(pid uint32) (name, cmdLine string) {
	t.procMu.RLock()
	if info, ok := t.procCache[pid]; ok {
		t.procMu.RUnlock()
		return info.name, info.command
	}
	t.procMu.RUnlock()

	// Get process name from /proc/[pid]/comm
	commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err == nil {
		name = strings.TrimSpace(string(commBytes))
	}

	// Get command line from /proc/[pid]/cmdline
	cmdLineBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err == nil {
		cmdLine = strings.ReplaceAll(string(cmdLineBytes), "\x00", " ")
		cmdLine = strings.TrimSpace(cmdLine)
	}

	// Cache the result
	t.procMu.Lock()
	t.procCache[pid] = processInfo{name: name, command: cmdLine}
	t.procMu.Unlock()

	return name, cmdLine
}

// parseHTTPData parses HTTP data from the event
func parseHTTPData(event *HTTPEvent) {
	data := string(event.Data[:event.DataLen])
	lines := strings.Split(data, "\r\n")
	if len(lines) == 0 {
		return
	}

	// Parse request line or status line
	firstLine := lines[0]
	if strings.HasPrefix(firstLine, "HTTP/") {
		// This is a response
		parts := strings.Split(firstLine, " ")
		if len(parts) >= 2 {
			event.StatusCode, _ = strconv.Atoi(parts[1])
		}
		// Look for Content-Type header
		for _, line := range lines[1:] {
			if strings.HasPrefix(line, "Content-Type:") {
				event.ContentType = strings.TrimSpace(
					strings.TrimPrefix(line, "Content-Type:"),
				)
				break
			}
		}
	} else {
		// This is a request
		parts := strings.Split(firstLine, " ")
		if len(parts) >= 2 {
			event.Method = parts[0]
			event.URL = parts[1]
		}
	}
}

// pollEvents reads events from the perf buffer
func (t *Tracer) pollEvents() {
	for {
		select {
		case <-t.stopChan:
			return
		default:
			// Read events from the ring buffer
			record, err := t.perfReader.Read()
			if err != nil {
				if err == perf.ErrClosed {
					return
				}
				t.logger.WithError(err).Error("Error reading from ring buffer")
				continue
			}

			t.logger.WithField("record", record).Debug("Received perf event")

			// Parse the event
			var event HTTPEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				t.logger.WithError(err).Error("Error parsing event")
				continue
			}

			t.logger.WithFields(logrus.Fields{
				"pid":     event.PID,
				"tid":     event.TID,
				"type":    event.Type,
				"conn_id": event.ConnID,
			}).Debug("Parsed HTTP event")

			// Get process info
			name, cmdLine := t.getProcessInfo(event.PID)
			event.ProcessName = name
			event.Command = cmdLine

			t.logger.WithFields(logrus.Fields{
				"pid":          event.PID,
				"process_name": event.ProcessName,
				"command":      event.Command,
			}).Debug("Retrieved process info")

			// Parse HTTP data
			parseHTTPData(&event)

			t.logger.WithFields(logrus.Fields{
				"pid":         event.PID,
				"method":      event.Method,
				"url":         event.URL,
				"status_code": event.StatusCode,
			}).Debug("Parsed HTTP data")

			// Log the event
			t.logger.WithFields(logrus.Fields{
				"type":         event.Type,
				"pid":          event.PID,
				"tid":          event.TID,
				"process_name": event.ProcessName,
				"command":      event.Command,
				"method":       event.Method,
				"url":          event.URL,
				"status_code":  event.StatusCode,
				"content_type": event.ContentType,
				"data_len":     event.DataLen,
				"data":         string(event.Data[:event.DataLen]),
			}).Info("HTTP event received")

			// Call the callback if set
			if t.eventCallback != nil {
				t.eventCallback(event)
			}
		}
	}
}

// Stop stops tracing HTTP traffic
func (t *Tracer) Stop() error {
	close(t.stopChan)
	return nil
}

// Close cleans up resources
func (t *Tracer) Close() error {
	t.Stop()

	// Clean up uprobes
	for _, uprobe := range t.uprobes {
		uprobe.Close()
	}

	// Close perf reader
	if t.perfReader != nil {
		t.perfReader.Close()
	}

	// Close BPF objects
	if t.objs != nil {
		t.objs.Close()
	}

	return nil
}

// SetEventCallback sets the callback function for HTTP events
func (t *Tracer) SetEventCallback(callback func(HTTPEvent)) {
	t.eventCallback = callback
}
