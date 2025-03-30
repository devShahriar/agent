package storage

import (
	"context"
	"sync"
	"time"

	"abproxy/pkg/tracer"
)

// HTTPTransaction represents a complete HTTP transaction with request and response
type HTTPTransaction struct {
	RequestTimestamp  time.Time         `json:"request_timestamp,omitempty"`
	ResponseTimestamp time.Time         `json:"response_timestamp,omitempty"`
	Duration          time.Duration     `json:"duration,omitempty"`
	ProcessID         uint32            `json:"pid"`
	ProcessName       string            `json:"process_name"`
	Command           string            `json:"command,omitempty"`
	Method            string            `json:"method,omitempty"`
	URL               string            `json:"url,omitempty"`
	StatusCode        int               `json:"status_code,omitempty"`
	ContentType       string            `json:"content_type,omitempty"`
	RequestSize       int               `json:"request_size,omitempty"`
	ResponseSize      int               `json:"response_size,omitempty"`
	RequestData       string            `json:"request_data,omitempty"`
	ResponseData      string            `json:"response_data,omitempty"`
	ConnID            uint32            `json:"conn_id"`
	PodName           string            `json:"pod_name,omitempty"`
	Namespace         string            `json:"namespace,omitempty"`
	NodeName          string            `json:"node_name,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
}

// TransactionProcessor handles the processing of HTTP transactions
type TransactionProcessor interface {
	// Process handles a completed HTTP transaction
	Process(ctx context.Context, tx *HTTPTransaction) error

	// Close cleans up any resources
	Close() error
}

// Storage is the interface for HTTP traffic storage backends
type Storage interface {
	// SaveEvent stores a raw eBPF event
	SaveEvent(ctx context.Context, event *tracer.HTTPEvent) error

	// SaveTransaction stores a complete HTTP transaction
	SaveTransaction(ctx context.Context, tx *HTTPTransaction) error

	// Close cleans up resources
	Close() error
}

// Manager manages HTTP transaction tracking and storage
type Manager struct {
	storage     Storage
	processor   TransactionProcessor
	connections map[uint32]*tracer.HTTPEvent
	mu          sync.RWMutex
}

// NewManager creates a new storage manager
func NewManager(storage Storage, processor TransactionProcessor) *Manager {
	return &Manager{
		storage:     storage,
		processor:   processor,
		connections: make(map[uint32]*tracer.HTTPEvent),
	}
}

// ProcessEvent handles an HTTPEvent from the tracer
func (m *Manager) ProcessEvent(ctx context.Context, event *tracer.HTTPEvent) error {
	// Always save the individual event
	if err := m.storage.SaveEvent(ctx, event); err != nil {
		return err
	}

	if event.Type == tracer.EventTypeSSLWrite {
		// It's a request, store it for correlation
		m.mu.Lock()
		m.connections[event.ConnID] = event.Clone() // Store a copy
		m.mu.Unlock()
		return nil
	} else if event.Type == tracer.EventTypeSSLRead {
		// It's a response, try to find matching request
		m.mu.Lock()
		reqEvent, exists := m.connections[event.ConnID]
		if exists {
			delete(m.connections, event.ConnID) // Remove after correlation
		}
		m.mu.Unlock()

		if exists {
			// Create a transaction from request and response
			tx := &HTTPTransaction{
				RequestTimestamp:  time.Unix(0, int64(reqEvent.Timestamp)),
				ResponseTimestamp: time.Unix(0, int64(event.Timestamp)),
				Duration:          time.Duration(event.Timestamp - reqEvent.Timestamp),
				ProcessID:         event.PID,
				ProcessName:       event.ProcessName,
				Command:           event.Command,
				Method:            reqEvent.Method,
				URL:               reqEvent.URL,
				StatusCode:        event.StatusCode,
				ContentType:       event.ContentType,
				RequestSize:       int(reqEvent.DataLen),
				ResponseSize:      int(event.DataLen),
				RequestData:       string(reqEvent.Data[:reqEvent.DataLen]),
				ResponseData:      string(event.Data[:event.DataLen]),
				ConnID:            event.ConnID,
				NodeName:          getNodeName(),
			}

			// Process the transaction (enrich, analyze, etc.)
			if m.processor != nil {
				if err := m.processor.Process(ctx, tx); err != nil {
					return err
				}
			}

			// Save the complete transaction
			return m.storage.SaveTransaction(ctx, tx)
		}
	}

	return nil
}

// CleanupOldConnections removes stale connections
func (m *Manager) CleanupOldConnections(maxAge time.Duration) {
	threshold := uint64(time.Now().Add(-maxAge).UnixNano())

	m.mu.Lock()
	defer m.mu.Unlock()

	for connID, event := range m.connections {
		if event.Timestamp < threshold {
			delete(m.connections, connID)
		}
	}
}

// Close cleans up resources
func (m *Manager) Close() error {
	var err1, err2 error

	if m.storage != nil {
		err1 = m.storage.Close()
	}

	if m.processor != nil {
		err2 = m.processor.Close()
	}

	if err1 != nil {
		return err1
	}
	return err2
}

// getNodeName returns the Kubernetes node name from environment
func getNodeName() string {
	// In a real implementation, this would read from the NODE_NAME environment variable
	// set in the Kubernetes pod spec
	return ""
}
