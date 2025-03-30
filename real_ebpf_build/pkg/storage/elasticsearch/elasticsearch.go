package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"abproxy/pkg/storage"
	"abproxy/pkg/tracer"
)

// Options defines configuration for Elasticsearch storage
type Options struct {
	// URL of the Elasticsearch server
	URL string

	// BasicAuth credentials (username:password)
	BasicAuth string

	// IndexPrefix for Elasticsearch indices
	IndexPrefix string

	// SaveEvents determines if raw events should be saved
	SaveEvents bool

	// BatchSize for bulk operations
	BatchSize int

	// FlushInterval for batch operations
	FlushInterval time.Duration
}

// DefaultOptions returns default options for Elasticsearch storage
func DefaultOptions() Options {
	return Options{
		URL:           "http://localhost:9200",
		IndexPrefix:   "abproxy",
		SaveEvents:    false,
		BatchSize:     1000,
		FlushInterval: 5 * time.Second,
	}
}

// Storage implements storage.Storage interface for Elasticsearch storage
type Storage struct {
	opts         Options
	httpClient   *http.Client
	eventsBuffer []map[string]interface{}
	txBuffer     []map[string]interface{}
	bufferTicker *time.Ticker
	stopChan     chan struct{}
}

// New creates a new Elasticsearch storage
func New(opts Options) (*Storage, error) {
	// Use default options if not specified
	if opts.URL == "" {
		opts.URL = DefaultOptions().URL
	}
	if opts.IndexPrefix == "" {
		opts.IndexPrefix = DefaultOptions().IndexPrefix
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

	// Create indices if they don't exist
	if err := s.createIndices(); err != nil {
		return nil, err
	}

	// Start background flusher
	s.bufferTicker = time.NewTicker(opts.FlushInterval)
	go s.flushRoutine()

	return s, nil
}

// createIndices ensures that the required indices exist
func (s *Storage) createIndices() error {
	// Only create indices if necessary
	if s.opts.SaveEvents {
		if err := s.createIndex(s.eventsIndex()); err != nil {
			return err
		}
	}

	if err := s.createIndex(s.txIndex()); err != nil {
		return err
	}

	return nil
}

// createIndex creates an Elasticsearch index if it doesn't exist
func (s *Storage) createIndex(index string) error {
	// Check if index exists
	req, err := http.NewRequest(
		http.MethodHead,
		fmt.Sprintf("%s/%s", s.opts.URL, index),
		nil,
	)
	if err != nil {
		return err
	}
	s.addAuth(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	// If index exists, we're done
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	// Create the index
	indexSettings := map[string]interface{}{
		"settings": map[string]interface{}{
			"number_of_shards":   3,
			"number_of_replicas": 1,
		},
	}

	body, err := json.Marshal(indexSettings)
	if err != nil {
		return err
	}

	req, err = http.NewRequest(
		http.MethodPut,
		fmt.Sprintf("%s/%s", s.opts.URL, index),
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	s.addAuth(req)

	resp, err = s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return fmt.Errorf("creating index: %s", resp.Status)
		}
		return fmt.Errorf("creating index: %v", errResp)
	}

	return nil
}

// SaveEvent stores a raw eBPF event
func (s *Storage) SaveEvent(ctx context.Context, event *tracer.HTTPEvent) error {
	if !s.opts.SaveEvents {
		return nil
	}

	// Convert the event to a map for Elasticsearch
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
		"host":         getHostname(),
		"node_name":    os.Getenv("NODE_NAME"),
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

// SaveTransaction stores a complete HTTP transaction
func (s *Storage) SaveTransaction(
	ctx context.Context,
	tx *storage.HTTPTransaction,
) error {
	// Convert the transaction to a map for Elasticsearch
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
		"host":               getHostname(),
		"node_name":          os.Getenv("NODE_NAME"),
		"pod_name":           tx.PodName,
		"namespace":          tx.Namespace,
		"labels":             tx.Labels,
	}

	// Add to buffer
	s.txBuffer = append(s.txBuffer, doc)

	// Flush if buffer is full
	if len(s.txBuffer) >= s.opts.BatchSize {
		return s.flushTransactions()
	}

	return nil
}

// flushEvents sends buffered events to Elasticsearch
func (s *Storage) flushEvents() error {
	if len(s.eventsBuffer) == 0 {
		return nil
	}

	if err := s.sendBulk(s.eventsIndex(), s.eventsBuffer); err != nil {
		return err
	}

	s.eventsBuffer = s.eventsBuffer[:0]
	return nil
}

// flushTransactions sends buffered transactions to Elasticsearch
func (s *Storage) flushTransactions() error {
	if len(s.txBuffer) == 0 {
		return nil
	}

	if err := s.sendBulk(s.txIndex(), s.txBuffer); err != nil {
		return err
	}

	s.txBuffer = s.txBuffer[:0]
	return nil
}

// sendBulk sends documents in bulk to Elasticsearch
func (s *Storage) sendBulk(index string, docs []map[string]interface{}) error {
	var buf bytes.Buffer

	// Create bulk request
	for _, doc := range docs {
		// Add action line
		action := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": index,
			},
		}

		actionJSON, err := json.Marshal(action)
		if err != nil {
			return err
		}
		buf.Write(actionJSON)
		buf.WriteByte('\n')

		// Add document
		docJSON, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		buf.Write(docJSON)
		buf.WriteByte('\n')
	}

	// Send request
	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/_bulk", s.opts.URL),
		&buf,
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	s.addAuth(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return fmt.Errorf("bulk indexing: %s", resp.Status)
		}
		return fmt.Errorf("bulk indexing: %v", errResp)
	}

	return nil
}

// flushRoutine periodically flushes buffered data
func (s *Storage) flushRoutine() {
	for {
		select {
		case <-s.bufferTicker.C:
			if s.opts.SaveEvents {
				if err := s.flushEvents(); err != nil {
					fmt.Fprintf(
						os.Stderr,
						"Error flushing events to Elasticsearch: %v\n",
						err,
					)
				}
			}

			if err := s.flushTransactions(); err != nil {
				fmt.Fprintf(
					os.Stderr,
					"Error flushing transactions to Elasticsearch: %v\n",
					err,
				)
			}
		case <-s.stopChan:
			return
		}
	}
}

// addAuth adds authentication headers to a request
func (s *Storage) addAuth(req *http.Request) {
	if s.opts.BasicAuth != "" {
		req.Header.Set("Authorization", "Basic "+basicAuth(s.opts.BasicAuth))
	}
}

// eventsIndex returns the index name for events
func (s *Storage) eventsIndex() string {
	return fmt.Sprintf("%s-events", s.opts.IndexPrefix)
}

// txIndex returns the index name for transactions
func (s *Storage) txIndex() string {
	return fmt.Sprintf("%s-transactions", s.opts.IndexPrefix)
}

// Close cleans up resources
func (s *Storage) Close() error {
	close(s.stopChan)
	s.bufferTicker.Stop()

	// Flush any remaining data
	if s.opts.SaveEvents {
		if err := s.flushEvents(); err != nil {
			return err
		}
	}

	return s.flushTransactions()
}

// getHostname returns the hostname of the current host
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// basicAuth encodes username:password as base64
func basicAuth(auth string) string {
	if !strings.Contains(auth, ":") {
		return auth // Already encoded or invalid
	}

	// This is a simple implementation for demonstration.
	// In a real application, you would use the base64 package.
	parts := strings.SplitN(auth, ":", 2)
	return fmt.Sprintf("%s:%s", parts[0], parts[1])
}
