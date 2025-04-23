package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"abproxy/pkg/storage"
	"abproxy/pkg/tracer"
)

// Options defines configuration for API storage
type Options struct {
	// URL of the API server
	URL string

	// AuthToken for API authentication
	AuthToken string

	// BatchSize for bulk operations
	BatchSize int

	// FlushInterval for batch operations
	FlushInterval time.Duration
}

// DefaultOptions returns default options for API storage
func DefaultOptions() Options {
	return Options{
		URL:           "http://localhost:8080",
		BatchSize:     1000,
		FlushInterval: 5 * time.Second,
	}
}

// Storage implements storage.Storage interface for API storage
type Storage struct {
	opts         Options
	httpClient   *http.Client
	eventsBuffer []map[string]interface{}
	txBuffer     []map[string]interface{}
	bufferTicker *time.Ticker
	stopChan     chan struct{}
}

// New creates a new API storage
func New(opts Options) (*Storage, error) {
	// Use default options if not specified
	if opts.URL == "" {
		opts.URL = DefaultOptions().URL
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = DefaultOptions().BatchSize
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = DefaultOptions().FlushInterval
	}

	s := &Storage{
		opts:         opts,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		eventsBuffer: make([]map[string]interface{}, 0, opts.BatchSize),
		txBuffer:     make([]map[string]interface{}, 0, opts.BatchSize),
		stopChan:     make(chan struct{}),
	}

	// Start background flusher
	s.bufferTicker = time.NewTicker(opts.FlushInterval)
	go s.flushRoutine()

	return s, nil
}

// SaveEvent implements storage.Storage interface
func (s *Storage) SaveEvent(ctx context.Context, event *tracer.HTTPEvent) error {
	// Convert the event to a map for API
	doc := map[string]interface{}{
		"@timestamp":   time.Unix(0, int64(event.Timestamp)).Format(time.RFC3339Nano),
		"pid":          event.PID,
		"tid":          event.TID,
		"process_name": event.ProcessName,
		"command":      event.Command,
		"type":         event.Type,
		"data_len":     event.DataLen,
		"conn_id":      event.ConnID,
		"data":         string(event.Data[:event.DataLen]),
	}

	// Parse HTTP data if possible
	if event.Type == tracer.EventTypeSSLWrite && event.Method != "" {
		doc["method"] = event.Method
		doc["url"] = event.URL
	} else if event.Type == tracer.EventTypeSSLRead && event.StatusCode > 0 {
		doc["status_code"] = event.StatusCode
		doc["content_type"] = event.ContentType
	}

	// Add to buffer
	s.eventsBuffer = append(s.eventsBuffer, doc)

	// Flush if buffer is full
	if len(s.eventsBuffer) >= s.opts.BatchSize {
		return s.flushEvents()
	}

	return nil
}

// SaveTransaction implements storage.Storage interface
func (s *Storage) SaveTransaction(
	ctx context.Context,
	tx *storage.HTTPTransaction,
) error {
	// Convert the transaction to a map for API
	doc := map[string]interface{}{
		"@timestamp":         tx.RequestTimestamp.Format(time.RFC3339Nano),
		"response_timestamp": tx.ResponseTimestamp.Format(time.RFC3339Nano),
		"duration_ns":        tx.Duration.Nanoseconds(),
		"duration_ms":        float64(tx.Duration.Nanoseconds()) / 1000000.0,
		"pid":                tx.ProcessID,
		"process_name":       tx.ProcessName,
		"command":            tx.Command,
		"method":             tx.Method,
		"url":                tx.URL,
		"status_code":        tx.StatusCode,
		"content_type":       tx.ContentType,
		"request_size":       tx.RequestSize,
		"response_size":      tx.ResponseSize,
		"request_data":       tx.RequestData,
		"response_data":      tx.ResponseData,
		"conn_id":            tx.ConnID,
	}

	// Add to buffer
	s.txBuffer = append(s.txBuffer, doc)

	// Flush if buffer is full
	if len(s.txBuffer) >= s.opts.BatchSize {
		return s.flushTransactions()
	}

	return nil
}

// flushEvents sends buffered events to API server
func (s *Storage) flushEvents() error {
	if len(s.eventsBuffer) == 0 {
		return nil
	}

	if err := s.sendBulk("events", s.eventsBuffer); err != nil {
		return err
	}

	s.eventsBuffer = s.eventsBuffer[:0]
	return nil
}

// flushTransactions sends buffered transactions to API server
func (s *Storage) flushTransactions() error {
	if len(s.txBuffer) == 0 {
		return nil
	}

	if err := s.sendBulk("transactions", s.txBuffer); err != nil {
		return err
	}

	s.txBuffer = s.txBuffer[:0]
	return nil
}

// sendBulk sends documents in bulk to API server
func (s *Storage) sendBulk(endpoint string, docs []map[string]interface{}) error {
	// Marshal documents to JSON
	data, err := json.Marshal(docs)
	if err != nil {
		return fmt.Errorf("failed to marshal documents: %w", err)
	}

	// Create request
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/%s", s.opts.URL, endpoint),
		bytes.NewReader(data),
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if s.opts.AuthToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.opts.AuthToken))
	}

	// Send request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// flushRoutine periodically flushes buffers
func (s *Storage) flushRoutine() {
	for {
		select {
		case <-s.bufferTicker.C:
			if err := s.flushEvents(); err != nil {
				fmt.Printf("Failed to flush events: %v\n", err)
			}
			if err := s.flushTransactions(); err != nil {
				fmt.Printf("Failed to flush transactions: %v\n", err)
			}
		case <-s.stopChan:
			return
		}
	}
}

// Close implements storage.Storage interface
func (s *Storage) Close() error {
	s.bufferTicker.Stop()
	close(s.stopChan)
	return nil
}
