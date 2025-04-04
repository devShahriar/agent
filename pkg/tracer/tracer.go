package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
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

//go:generate sh -c "if [ \"$(uname -s)\" != \"Darwin\" ]; then go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags \"-O2 -g -Wall -Werror -nostdinc -D__x86_64__ -D__TARGET_ARCH_x86_64 -D__KERNEL__ -D__BPF_TRACING__ -DBPF_NO_PRESERVE_ACCESS_INDEX -I/usr/include/x86_64-linux-gnu -I/usr/include/x86_64-linux-gnu/sys -I/usr/lib/llvm-10/lib/clang/10.0.0/include -I/usr/include/linux -I/usr/include/bpf -DHAVE_NO_VDSO -DNO_CORE_RELOC -DCORE_DISABLE_VDSO_LOOKUP -DSKIP_KERNEL_VERSION=1 -DBPF_NO_PRESERVE_ACCESS_INDEX=1 -D__BPF_TRACING__ -D__BPF_CORE_READ__\" -no-strip -target bpfel -type trace_event_raw_sys_enter -type trace_event_raw_sys_exit bpf ./bpf/http_trace.c; else echo 'Skipping go:generate on Darwin'; fi"

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

// HTTPTransaction represents a complete HTTP transaction with request and response
type HTTPTransaction struct {
	Request     *HTTPEvent
	Response    *HTTPEvent
	StartTime   time.Time
	EndTime     time.Time
	Duration    time.Duration
	ProcessName string
	Command     string
}

// Clone returns a copy of the HTTPEvent
func (e *HTTPEvent) Clone() *HTTPEvent {
	clone := *e // Shallow copy
	return &clone
}

// Storage interface for storing HTTP events
type Storage interface {
	Store(event HTTPEvent) error
	StoreTransaction(transaction HTTPTransaction) error
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

// StoreTransaction implements Storage interface
func (s *FileStorage) StoreTransaction(transaction HTTPTransaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Format request and response data for human-readable storage
	requestFormatted := FormatHTTPData(transaction.Request)
	var responseFormatted string
	if transaction.Response != nil {
		responseFormatted = FormatHTTPData(transaction.Response)
	}

	// Create a filename based on timestamp and PID
	filename := fmt.Sprintf("%s/http_tx_%s_%d_%d.json",
		s.dir,
		transaction.ProcessName,
		transaction.Request.PID,
		transaction.Request.Timestamp)

	// Create the document
	doc := map[string]interface{}{
		"start_time":   transaction.StartTime,
		"end_time":     transaction.EndTime,
		"duration_ms":  transaction.Duration.Milliseconds(),
		"process_name": transaction.ProcessName,
		"command":      transaction.Command,
		"request": map[string]interface{}{
			"method": transaction.Request.Method,
			"url":    transaction.Request.URL,
			"raw_data": string(
				transaction.Request.Data[:transaction.Request.DataLen],
			),
			"formatted_data": requestFormatted,
		},
	}

	// Add response if available
	if transaction.Response != nil {
		doc["response"] = map[string]interface{}{
			"status_code":  transaction.Response.StatusCode,
			"content_type": transaction.Response.ContentType,
			"raw_data": string(
				transaction.Response.Data[:transaction.Response.DataLen],
			),
			"formatted_data": responseFormatted,
		}
	}

	// Marshal the document to JSON
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal transaction document: %w", err)
	}

	// Write the file
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write transaction file: %w", err)
	}

	s.logger.WithField("filename", filename).Debug("Stored HTTP transaction")
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

	s.logger.WithFields(logrus.Fields{
		"index": s.index,
		"url":   s.url,
		"id":    req.DocumentID,
	}).Debug("Indexing HTTP event in Elasticsearch")

	// Perform the request
	res, err := req.Do(context.Background(), s.client)
	if err != nil {
		s.logger.WithError(err).Error("Failed to send request to Elasticsearch")
		return fmt.Errorf("failed to index document: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		responseBody, _ := io.ReadAll(res.Body)
		s.logger.WithFields(logrus.Fields{
			"status_code": res.StatusCode,
			"response":    string(responseBody),
		}).Error("Error response from Elasticsearch")
		return fmt.Errorf("error indexing document: %s", res.String())
	}

	s.logger.WithFields(logrus.Fields{
		"index": s.index,
		"id":    req.DocumentID,
	}).Debug("Successfully indexed HTTP event in Elasticsearch")

	return nil
}

// StoreTransaction implements Storage interface
func (s *ElasticsearchStorage) StoreTransaction(transaction HTTPTransaction) error {
	// Format request and response data for human-readable storage
	requestFormatted := FormatHTTPData(transaction.Request)
	var responseFormatted string
	if transaction.Response != nil {
		responseFormatted = FormatHTTPData(transaction.Response)
	}

	// Try to parse request and response body as JSON if possible
	requestBody := parseBodyAsJSON(transaction.Request)
	var responseBody interface{}
	if transaction.Response != nil {
		responseBody = parseBodyAsJSON(transaction.Response)
	}

	// Create the document
	doc := map[string]interface{}{
		"start_time":   transaction.StartTime,
		"end_time":     transaction.EndTime,
		"duration_ms":  transaction.Duration.Milliseconds(),
		"service_name": transaction.ProcessName,
		"command":      transaction.Command,
		"timestamp":    time.Now().Format(time.RFC3339),
		"request": map[string]interface{}{
			"method": transaction.Request.Method,
			"url":    transaction.Request.URL,
			"raw_data": string(
				transaction.Request.Data[:transaction.Request.DataLen],
			),
			"formatted_data": requestFormatted,
			"body":           requestBody,
		},
	}

	// Add response if available
	if transaction.Response != nil {
		doc["response"] = map[string]interface{}{
			"status_code":  transaction.Response.StatusCode,
			"content_type": transaction.Response.ContentType,
			"raw_data": string(
				transaction.Response.Data[:transaction.Response.DataLen],
			),
			"formatted_data": responseFormatted,
			"body":           responseBody,
		}
	}

	// Marshal the document to JSON
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction document: %w", err)
	}

	// Create a more descriptive index name
	indexName := fmt.Sprintf(
		"%s-http-transactions-%s",
		s.index,
		time.Now().Format("2006-01-02"),
	)

	// Create a unique ID for the transaction
	docID := fmt.Sprintf(
		"%d-%d-%d",
		transaction.Request.PID,
		transaction.Request.TID,
		transaction.Request.Timestamp,
	)

	// Create the index request with dynamic index name
	req := esapi.IndexRequest{
		Index:      indexName,
		DocumentID: docID,
		Body:       bytes.NewReader(data),
		Refresh:    "true",
	}

	s.logger.WithFields(logrus.Fields{
		"index":        indexName,
		"url":          s.url,
		"id":           docID,
		"method":       transaction.Request.Method,
		"request_url":  transaction.Request.URL,
		"status_code":  getResponseStatusCode(transaction.Response),
		"service_name": transaction.ProcessName,
	}).Info("Indexing HTTP transaction in Elasticsearch")

	// Perform the request
	res, err := req.Do(context.Background(), s.client)
	if err != nil {
		s.logger.WithError(err).Error("Failed to send transaction to Elasticsearch")
		return fmt.Errorf("failed to index transaction document: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		responseData, _ := io.ReadAll(res.Body)
		s.logger.WithFields(logrus.Fields{
			"status_code": res.StatusCode,
			"response":    string(responseData),
			"index":       indexName,
		}).Error("Error response from Elasticsearch when indexing transaction")
		return fmt.Errorf("error indexing transaction document: %s", res.String())
	}

	s.logger.WithFields(logrus.Fields{
		"index":        indexName,
		"id":           docID,
		"method":       transaction.Request.Method,
		"request_url":  transaction.Request.URL,
		"service_name": transaction.ProcessName,
	}).Info("Successfully indexed HTTP transaction in Elasticsearch")

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
	connections map[string]*HTTPEvent

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
		connections:   make(map[string]*HTTPEvent),
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
	// Skip invalid PIDs
	if pid == 0 || pid > 1000000 {
		return "unknown", "unknown"
	}

	t.procMu.RLock()
	if info, ok := t.procCache[pid]; ok {
		t.procMu.RUnlock()
		return info.name, info.command
	}
	t.procMu.RUnlock()

	name = "unknown"
	cmdLine = "unknown"

	// Get process name from /proc/[pid]/comm
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	if _, err := os.Stat(commPath); err == nil {
		commBytes, err := os.ReadFile(commPath)
		if err == nil {
			name = strings.TrimSpace(string(commBytes))
		}
	}

	// Get command line from /proc/[pid]/cmdline
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	if _, err := os.Stat(cmdlinePath); err == nil {
		cmdLineBytes, err := os.ReadFile(cmdlinePath)
		if err == nil {
			cmdLine = strings.ReplaceAll(string(cmdLineBytes), "\x00", " ")
			cmdLine = strings.TrimSpace(cmdLine)
		}
	}

	// Cache the result
	t.procMu.Lock()
	t.procCache[pid] = processInfo{name: name, command: cmdLine}
	t.procMu.Unlock()

	return name, cmdLine
}

// parseHTTPData parses HTTP data from the event
func parseHTTPData(event *HTTPEvent) {
	// Safety check to ensure we don't exceed buffer bounds
	if event.DataLen == 0 || event.DataLen > uint32(len(event.Data)) {
		return
	}

	data := string(event.Data[:event.DataLen])
	lines := strings.Split(data, "\r\n")
	if len(lines) == 0 {
		return
	}

	// Parse request line or status line
	firstLine := lines[0]
	headers := make(map[string]string)

	// Find the empty line that separates headers from body
	bodyStart := -1
	for i, line := range lines {
		if line == "" && i < len(lines)-1 {
			bodyStart = i + 1
			break
		}
	}

	// Parse headers
	for i := 1; i < len(lines) && (bodyStart == -1 || i < bodyStart); i++ {
		if lines[i] == "" {
			continue
		}
		parts := strings.SplitN(lines[i], ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			headers[key] = value
		}
	}

	if strings.HasPrefix(firstLine, "HTTP/") {
		// This is a response
		parts := strings.Split(firstLine, " ")
		if len(parts) >= 2 {
			event.StatusCode, _ = strconv.Atoi(parts[1])
		}
		// Get Content-Type header
		if contentType, ok := headers["Content-Type"]; ok {
			event.ContentType = contentType
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

// FormatHTTPData returns a human-readable formatted version of HTTP data
func FormatHTTPData(event *HTTPEvent) string {
	if event == nil || event.DataLen == 0 {
		return ""
	}

	// Clean up the data by removing null bytes and control characters except newlines
	cleanData := make([]byte, 0, event.DataLen)
	for i := 0; i < int(event.DataLen); i++ {
		b := event.Data[i]
		// Skip null bytes and most control characters except newlines, returns, tabs
		if b == 0 || (b < 32 && b != '\n' && b != '\r' && b != '\t') {
			continue
		}
		// Skip non-printable high bytes
		if b > 127 {
			continue
		}
		cleanData = append(cleanData, b)
	}

	// Convert to string after cleaning
	data := string(cleanData)

	// Handle HTTP data that starts with null bytes followed by HTTP
	if strings.Contains(data, "HTTP/1.1") && !strings.HasPrefix(data, "HTTP/1.1") {
		index := strings.Index(data, "HTTP/1.1")
		if index > 0 {
			data = data[index:]
		}
	}

	// Same for request methods
	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"} {
		if strings.Contains(data, method+" ") && !strings.HasPrefix(data, method+" ") {
			index := strings.Index(data, method+" ")
			if index > 0 {
				data = data[index:]
			}
			break
		}
	}

	lines := strings.Split(data, "\r\n")
	if len(lines) == 1 {
		// Try splitting by newline if CR+LF doesn't work
		lines = strings.Split(data, "\n")
	}

	if len(lines) == 0 {
		return data // Return raw data if we can't parse into lines
	}

	// Format headers and body with proper indentation
	var formatted strings.Builder

	// Handle request/response line
	if len(lines[0]) > 0 {
		formatted.WriteString(lines[0])
		formatted.WriteString("\n")
	}

	// Track headers and body
	inHeaders := true
	bodyContent := ""
	headers := make(map[string]string)

	// Add headers and detect body
	for i := 1; i < len(lines); i++ {
		if lines[i] == "" {
			inHeaders = false
			formatted.WriteString("\n")
			continue
		}

		if inHeaders {
			formatted.WriteString("  ")
			formatted.WriteString(lines[i])
			formatted.WriteString("\n")

			// Parse headers for later use
			parts := strings.SplitN(lines[i], ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				headers[key] = value
			}
		} else {
			// Collect body content
			if bodyContent == "" {
				bodyContent = lines[i]
			} else {
				bodyContent += "\n" + lines[i]
			}
		}
	}

	// Format body if present
	if bodyContent != "" {
		// Try to detect and format JSON
		if strings.Contains(strings.ToLower(data), "content-type: application/json") ||
			strings.Contains(strings.ToLower(data), "content-type:application/json") {
			var jsonData interface{}
			if err := json.Unmarshal([]byte(bodyContent), &jsonData); err == nil {
				// Pretty-print JSON
				prettyJSON, err := json.MarshalIndent(jsonData, "  ", "  ")
				if err == nil {
					formatted.WriteString("  Body (JSON):\n  ")
					formatted.WriteString(string(prettyJSON))
					return formatted.String()
				}
			}
		}

		// Regular body formatting
		formatted.WriteString("  Body:\n  ")
		formatted.WriteString(strings.ReplaceAll(bodyContent, "\n", "\n  "))
	}

	return formatted.String()
}

// parseBodyAsJSON attempts to parse an HTTP event body as JSON
func parseBodyAsJSON(event *HTTPEvent) interface{} {
	if event == nil || event.DataLen == 0 {
		return nil
	}

	// Get the HTTP data
	data := string(event.Data[:event.DataLen])

	// Find the body part (after empty line)
	parts := strings.Split(data, "\r\n\r\n")
	if len(parts) < 2 {
		// Try with just newlines
		parts = strings.Split(data, "\n\n")
		if len(parts) < 2 {
			return nil
		}
	}

	bodyData := parts[1]

	// Try to parse as JSON
	var result interface{}
	if err := json.Unmarshal([]byte(bodyData), &result); err == nil {
		return result
	}

	return nil
}

// pollEvents reads events from the perf buffer
func (t *Tracer) pollEvents() {
	var httpEvent HTTPEvent

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

			// Skip if record is too small or missing
			if record.RawSample == nil || len(record.RawSample) < 4 {
				t.logger.Debug("Skipping empty or too small record")
				continue
			}

			t.logger.WithField("record_size", len(record.RawSample)).
				Debug("Received perf event")

			// Create a temp struct that matches the BPF binary format
			type bpfEvent struct {
				PID       uint32
				TID       uint32
				Timestamp uint64
				FD        uint32
				Type      uint8
				DataLen   uint32
				Data      [256]byte
			}

			var bpfData bpfEvent

			// Parse the event using the correct struct
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &bpfData); err != nil {
				t.logger.WithError(err).Error("Error parsing raw event")
				continue
			}

			// Basic validation of event data
			if bpfData.Type < 1 || bpfData.Type > 4 {
				t.logger.WithFields(logrus.Fields{
					"invalid_type": bpfData.Type,
				}).Debug("Skipping event with invalid type")
				continue
			}

			if bpfData.Timestamp == 0 {
				t.logger.Debug("Skipping event with zero timestamp")
				continue
			}

			// Filter only known large garbage sizes, but keep logging for debugging
			knownGarbageSizes := []uint32{1543503872, 1979711488}
			isKnownGarbage := false
			for _, size := range knownGarbageSizes {
				if bpfData.DataLen == size {
					isKnownGarbage = true
					break
				}
			}

			if isKnownGarbage {
				// Silently skip known garbage
				continue
			}

			// Log large data sizes but don't filter out all large packets
			if bpfData.DataLen > 10000 {
				t.logger.WithFields(logrus.Fields{
					"pid":         bpfData.PID,
					"claimed_len": bpfData.DataLen,
				}).Debug("Large data size detected")
			}

			// Convert to our HTTPEvent struct
			httpEvent.PID = bpfData.PID
			httpEvent.TID = bpfData.TID
			httpEvent.Timestamp = bpfData.Timestamp
			httpEvent.ConnID = bpfData.FD
			httpEvent.Type = bpfData.Type

			// Ensure data length is valid (cap at buffer size)
			if bpfData.DataLen > uint32(len(httpEvent.Data)) {
				t.logger.WithFields(logrus.Fields{
					"pid":         bpfData.PID,
					"claimed_len": bpfData.DataLen,
					"max_len":     len(httpEvent.Data),
				}).Debug("Truncating oversized data length")
				httpEvent.DataLen = uint32(len(httpEvent.Data))
			} else {
				httpEvent.DataLen = bpfData.DataLen
			}

			// Skip if data length is zero
			if httpEvent.DataLen == 0 {
				t.logger.Debug("Skipping event with zero data length")
				continue
			}

			copy(httpEvent.Data[:], bpfData.Data[:])

			// Get process info
			name, cmdLine := t.getProcessInfo(httpEvent.PID)
			httpEvent.ProcessName = name
			httpEvent.Command = cmdLine

			// Log the raw event data to help with debugging
			t.logger.WithFields(logrus.Fields{
				"pid":          httpEvent.PID,
				"process_name": httpEvent.ProcessName,
				"command":      httpEvent.Command,
				"data_len":     httpEvent.DataLen,
				"conn_id":      httpEvent.ConnID,
				"type":         httpEvent.Type,
				"timestamp":    httpEvent.Timestamp,
			}).Debug("Raw event details")

			// Skip unwanted processes early to avoid unnecessary processing
			// Explicitly check for kubelet and cilium-agent as requested
			if httpEvent.ProcessName == "coredns" ||
				httpEvent.ProcessName == "kubelet" ||
				httpEvent.ProcessName == "cilium-agent" ||
				strings.Contains(strings.ToLower(httpEvent.Command), "coredns") ||
				strings.Contains(strings.ToLower(httpEvent.Command), "kubelet") ||
				strings.Contains(strings.ToLower(httpEvent.Command), "cilium-agent") {
				t.logger.WithFields(logrus.Fields{
					"process_name": httpEvent.ProcessName,
					"command":      httpEvent.Command,
				}).Debug("Skipping ignored process")
				continue
			}

			// Parse HTTP data
			parseHTTPData(&httpEvent)

			t.logger.WithFields(logrus.Fields{
				"pid":         httpEvent.PID,
				"method":      httpEvent.Method,
				"url":         httpEvent.URL,
				"status_code": httpEvent.StatusCode,
			}).Debug("Parsed HTTP data")

			// Log the event
			formattedData := FormatHTTPData(&httpEvent)
			t.logger.WithFields(logrus.Fields{
				"type":         httpEvent.Type,
				"pid":          httpEvent.PID,
				"tid":          httpEvent.TID,
				"process_name": httpEvent.ProcessName,
				"command":      httpEvent.Command,
				"method":       httpEvent.Method,
				"url":          httpEvent.URL,
				"status_code":  httpEvent.StatusCode,
				"content_type": httpEvent.ContentType,
				"data_len":     httpEvent.DataLen,
				"http_data":    formattedData,
			}).Info("HTTP event received")

			// Handle the event - track request and response pairs
			eventCopy := httpEvent.Clone()
			t.handleHTTPEvent(eventCopy)

			// Store the event if storage is available
			if t.storage != nil {
				if err := t.storage.Store(httpEvent); err != nil {
					t.logger.WithError(err).Error("Failed to store HTTP event")
				}
			}

			// Call the callback if set
			if t.eventCallback != nil {
				t.eventCallback(httpEvent)
			}
		}
	}
}

// IsRelevantApplication determines if the process is one we want detailed logs for
func IsRelevantApplication(processName, command string) bool {
	// Focus on our dummy HTTP server/client or other specific applications
	relevantProcesses := []string{
		"gunicorn",
		"python",
		"curl",
		"httpbin",
		"dummy",
		"go-test",
	}

	// Processes to always ignore
	ignoredProcesses := []string{
		"kubelet",      // Explicitly ignore kubelet
		"cilium-agent", // Explicitly ignore cilium-agent
		"kube-proxy",
		"coredns",
		"kube-apiserver",
		"kube-scheduler",
		"kube-controller",
		"etcd",
		"flanneld",
		"calico",
		"cilium",
		"containerd",
		"crio",
		"dockerd",
		"flannel",
		"metrics-server",
		"k8s",
		"kubernetes",
	}

	processNameLower := strings.ToLower(processName)
	commandLower := strings.ToLower(command)

	// First check if it's in the ignored list
	for _, proc := range ignoredProcesses {
		if strings.Contains(processNameLower, proc) ||
			strings.Contains(commandLower, proc) {
			return false
		}
	}

	// Common command patterns to ignore
	ignoredPatterns := []string{
		"/var/lib/kubelet",
		"/var/lib/containerd",
		"/var/run/kubernetes",
		"/etc/kubernetes",
		"/usr/local/bin/kube",
		"--kubeconfig",
		"--node-name",
		"--cluster-",
		"-namespace=kube",
		"-namespace monitoring",
		"/opt/cni/bin",   // Added to ignore CNI-related processes
		"/etc/cni/net.d", // Added to ignore CNI config related processes
	}

	for _, pattern := range ignoredPatterns {
		if strings.Contains(commandLower, pattern) {
			return false
		}
	}

	// Check process name
	for _, proc := range relevantProcesses {
		if strings.Contains(processNameLower, proc) {
			return true
		}
	}

	// Check command
	for _, proc := range relevantProcesses {
		if strings.Contains(commandLower, proc) {
			return true
		}
	}

	return false
}

// IsHealthCheck determines if a URL is a health check endpoint or Kubernetes API call
func IsHealthCheck(url string) bool {
	if url == "" {
		return false
	}

	// Kubernetes API path patterns
	kubeApiPatterns := []string{
		"/api/v1/",
		"/apis/",
		"/metrics",
		"/openapi",
		"/version",
		"/healthz",
		"/livez",
		"/readyz",
		"/logs",
		"/kube-",
		"/swagger",
	}

	for _, pattern := range kubeApiPatterns {
		if strings.Contains(url, pattern) {
			return true
		}
	}

	healthPaths := []string{
		"/health",
		"/healthz",
		"/ready",
		"/readyz",
		"/alive",
		"/ping",
		"/status",
		"/metrics",
		"/livez",
		// Kubelet specific paths
		"/pods",
		"/stats",
		"/containerLogs",
		"/run",
		"/exec",
		"/attach",
		"/portForward",
		"/cri",
		"/debug/",
		"/node/",
		"/proxy/",
		"proxy?path=",
	}

	// Common query parameters used in health checks
	if strings.Contains(url, "?watch=") ||
		strings.Contains(url, "healthz") ||
		strings.Contains(url, "health?") ||
		strings.Contains(url, "ready?") ||
		strings.Contains(url, "alive?") ||
		strings.Contains(url, "ping?") {
		return true
	}

	urlLower := strings.ToLower(url)
	for _, path := range healthPaths {
		if strings.Contains(urlLower, path) {
			return true
		}
	}

	return false
}

// handleHTTPEvent processes an HTTP event to track transactions
func (t *Tracer) handleHTTPEvent(event *HTTPEvent) {
	t.connMu.Lock()
	defer t.connMu.Unlock()

	// Create connection key from process ID and connection ID
	connKey := fmt.Sprintf("%d:%d", event.PID, event.ConnID)

	// Format the event data for human-readable output
	formattedData := FormatHTTPData(event)

	// If it's a request (write event)
	if event.Type == EventTypeSSLWrite || event.Type == EventTypeSocketWrite {
		// Store the request in the connection map
		t.connections[connKey] = event

		// Log information about the request
		t.logger.WithFields(logrus.Fields{
			"conn_key": connKey,
			"method":   event.Method,
			"url":      event.URL,
			"data":     formattedData,
		}).Debug("Stored HTTP request")
	} else if event.Type == EventTypeSSLRead || event.Type == EventTypeSocketRead {
		// It's a response - look for the matching request
		if req, ok := t.connections[connKey]; ok {
			// We found a matching request, create a transaction
			tx := HTTPTransaction{
				Request:     req,
				Response:    event,
				StartTime:   time.Unix(0, int64(req.Timestamp)),
				EndTime:     time.Unix(0, int64(event.Timestamp)),
				ProcessName: event.ProcessName,
				Command:     event.Command,
			}
			tx.Duration = tx.EndTime.Sub(tx.StartTime)

			// Format request and response data
			reqFormatted := FormatHTTPData(req)
			respFormatted := formattedData

			// Log the complete transaction
			t.logger.WithFields(logrus.Fields{
				"method":      req.Method,
				"url":         req.URL,
				"status_code": event.StatusCode,
				"duration_ms": tx.Duration.Milliseconds(),
				"process":     tx.ProcessName,
				"request":     reqFormatted,
				"response":    respFormatted,
				"conn_key":    connKey,
			}).Info("HTTP Transaction completed")

			// Store the transaction
			if t.storage != nil {
				if err := t.storage.StoreTransaction(tx); err != nil {
					t.logger.WithError(err).Error("Failed to store HTTP transaction")
				}
			}

			// Remove the request from the map
			delete(t.connections, connKey)
		} else {
			// We got a response without a matching request
			t.logger.WithFields(logrus.Fields{
				"conn_key":    connKey,
				"status_code": event.StatusCode,
				"data":        formattedData,
			}).Debug("Received orphaned HTTP response")
		}
	}

	// Cleanup old requests (incomplete transactions)
	now := time.Now().UnixNano()
	for key, req := range t.connections {
		// If request is older than 30 seconds, remove it
		if now-int64(req.Timestamp) > 30*int64(time.Second) {
			t.logger.WithField("conn_key", key).Debug("Removing stale HTTP request")
			delete(t.connections, key)
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

// Helper function to get response status code safely
func getResponseStatusCode(response *HTTPEvent) int {
	if response != nil {
		return response.StatusCode
	}
	return 0
}
