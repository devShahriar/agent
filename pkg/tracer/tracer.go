package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/sirupsen/logrus"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I./bpf" bpf ./bpf/http_trace.c

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
	objs          *bpfObjects
	perfReader    *perf.Reader
	logger        *logrus.Logger
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
	paths := []string{
		"/usr/lib/libssl.so.3",
		"/usr/lib/libssl.so.1.1",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/usr/lib/aarch64-linux-gnu/libssl.so.3",
		"/usr/lib/aarch64-linux-gnu/libssl.so.1.1",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("could not find libssl.so")
}

// NewTracer creates a new HTTP tracer
func NewTracer(logger *logrus.Logger, callback func(HTTPEvent)) (*Tracer, error) {
	t := &Tracer{
		logger:        logger,
		eventCallback: callback,
		stopChan:      make(chan struct{}),
		uprobes:       make([]link.Link, 0),
		connections:   make(map[uint32]*HTTPEvent),
		procCache:     make(map[uint32]processInfo),
	}

	// Load pre-compiled programs with modified options
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 1,
			LogSize:  65535,
		},
		Maps: ebpf.MapOptions{
			// Pinning is required for some kernels
			PinPath: "/sys/fs/bpf",
		},
	}

	objs, err := loadBpfObjects(opts)
	if err != nil {
		if logger != nil {
			logger.WithError(err).Error("Failed to load BPF objects")
		}
		return nil, fmt.Errorf("loading objects: %w", err)
	}
	t.objs = objs

	// Initialize perf reader for the events map
	if t.objs.Events != nil {
		rd, err := perf.NewReader(t.objs.Events, os.Getpagesize()*16)
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("creating perf reader: %w", err)
		}
		t.perfReader = rd
	}

	return t, nil
}

// Start begins tracing HTTP traffic
func (t *Tracer) Start() error {
	// Find SSL library
	sslPath, err := findSSLPath()
	if err != nil {
		return fmt.Errorf("finding SSL library: %w", err)
	}

	// Open the SSL library
	ex, err := link.OpenExecutable(sslPath)
	if err != nil {
		return fmt.Errorf("opening SSL library: %w", err)
	}

	// Attach to SSL_read with retries
	for i := 0; i < 3; i++ {
		readUprobe, err := ex.Uprobe(
			"SSL_read",
			t.objs.TraceSslRead,
			&link.UprobeOptions{},
		)
		if err == nil {
			t.uprobes = append(t.uprobes, readUprobe)
			break
		}
		if i == 2 {
			return fmt.Errorf("attaching SSL_read uprobe: %w", err)
		}
		t.logger.WithError(err).Warn("Retrying SSL_read uprobe attachment")
	}

	// Attach to SSL_write with retries
	for i := 0; i < 3; i++ {
		writeUprobe, err := ex.Uprobe(
			"SSL_write",
			t.objs.TraceSslWrite,
			&link.UprobeOptions{},
		)
		if err == nil {
			t.uprobes = append(t.uprobes, writeUprobe)
			break
		}
		if i == 2 {
			return fmt.Errorf("attaching SSL_write uprobe: %w", err)
		}
		t.logger.WithError(err).Warn("Retrying SSL_write uprobe attachment")
	}

	// Start polling for events
	go t.pollEvents()

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

// parseHTTPData attempts to parse HTTP data from the raw buffer
func parseHTTPData(event *HTTPEvent) {
	data := string(event.Data[:event.DataLen])

	// Basic parsing for HTTP data
	if event.Type == EventTypeSSLWrite { // Request
		if parts := strings.Split(data, "\r\n"); len(parts) > 0 {
			requestLine := parts[0]
			if requestParts := strings.Split(requestLine, " "); len(requestParts) >= 2 {
				event.Method = requestParts[0]
				event.URL = requestParts[1]
			}
		}
	} else if event.Type == EventTypeSSLRead { // Response
		if parts := strings.Split(data, "\r\n"); len(parts) > 0 {
			statusLine := parts[0]
			if strings.HasPrefix(statusLine, "HTTP/") {
				if statusParts := strings.Split(statusLine, " "); len(statusParts) >= 2 {
					fmt.Sscanf(statusParts[1], "%d", &event.StatusCode)
				}
			}

			// Look for Content-Type header
			for _, line := range parts {
				if strings.HasPrefix(strings.ToLower(line), "content-type:") {
					event.ContentType = strings.TrimSpace(line[13:])
					break
				}
			}
		}
	}
}

// pollEvents reads events from the perf buffer
func (t *Tracer) pollEvents() {
	var event HTTPEvent

	for {
		select {
		case <-t.stopChan:
			return
		default:
			if t.perfReader == nil {
				if t.logger != nil {
					t.logger.Info("Perf reader not available")
				}
				return
			}

			record, err := t.perfReader.Read()
			if err != nil {
				if err == perf.ErrClosed {
					return
				}
				t.logger.WithError(err).Error("Error reading perf event")
				continue
			}

			if record.LostSamples != 0 {
				t.logger.WithField("lost", record.LostSamples).Warn("Lost samples")
				continue
			}

			// Parse the raw event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				t.logger.WithError(err).Error("Error parsing event")
				continue
			}

			// Get process information
			event.ProcessName, event.Command = t.getProcessInfo(event.PID)

			// Parse HTTP data
			parseHTTPData(&event)

			// Track connections to correlate requests and responses
			if event.Type == EventTypeSSLWrite {
				// Save request for correlation with response
				t.connMu.Lock()
				t.connections[event.ConnID] = &event
				t.connMu.Unlock()
			} else if event.Type == EventTypeSSLRead {
				// Try to correlate with existing request
				t.connMu.RLock()
				reqEvent, exists := t.connections[event.ConnID]
				t.connMu.RUnlock()

				if exists {
					// Can add correlation info here if needed
					t.logger.WithFields(logrus.Fields{
						"url":    reqEvent.URL,
						"method": reqEvent.Method,
						"status": event.StatusCode,
					}).Debug("Correlated request-response")
				}
			}

			// Call the callback with the event
			if t.eventCallback != nil {
				t.eventCallback(event)
			}
		}
	}
}

// Stop stops the tracer
func (t *Tracer) Stop() error {
	close(t.stopChan)
	if t.perfReader != nil {
		t.perfReader.Close()
	}

	// Close all uprobes
	for _, uprobe := range t.uprobes {
		uprobe.Close()
	}

	return nil
}

// Close cleans up resources
func (t *Tracer) Close() error {
	if err := t.Stop(); err != nil {
		return err
	}
	if t.objs != nil {
		return t.objs.Close()
	}
	return nil
}
