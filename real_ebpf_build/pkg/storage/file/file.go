package file

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"abproxy/pkg/storage"
	"abproxy/pkg/tracer"
)

// Options defines configuration for file-based storage
type Options struct {
	// Directory where event and transaction files will be stored
	Directory string

	// Prefix for all event and transaction files
	Prefix string

	// SaveEvents determines if raw events should be saved
	SaveEvents bool

	// RawFormat determines if the data should be saved in raw format
	RawFormat bool

	// MaxFileSize is the maximum size in bytes before rotating to a new file
	MaxFileSize int64

	// Permissions for created files (default: 0644)
	FileMode os.FileMode
}

// DefaultOptions returns default options for file storage
func DefaultOptions() Options {
	return Options{
		Directory:   "./data",
		Prefix:      "http-traffic",
		SaveEvents:  false,
		RawFormat:   false,
		MaxFileSize: 100 * 1024 * 1024, // 100MB
		FileMode:    0644,
	}
}

// Storage implements storage.Storage interface for file-based storage
type Storage struct {
	opts          Options
	eventsFile    *os.File
	txFile        *os.File
	eventsSize    int64
	txSize        int64
	mu            sync.Mutex
	eventsCounter int64
	txCounter     int64
}

// New creates a new file-based storage
func New(opts Options) (*Storage, error) {
	// Use default options if not specified
	if opts.Directory == "" {
		opts.Directory = DefaultOptions().Directory
	}
	if opts.Prefix == "" {
		opts.Prefix = DefaultOptions().Prefix
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultOptions().MaxFileSize
	}
	if opts.FileMode == 0 {
		opts.FileMode = DefaultOptions().FileMode
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(opts.Directory, 0755); err != nil {
		return nil, fmt.Errorf("creating storage directory: %w", err)
	}

	s := &Storage{
		opts: opts,
	}

	// Open initial files if needed
	if opts.SaveEvents {
		if err := s.rotateEventsFile(); err != nil {
			return nil, err
		}
	}

	if err := s.rotateTxFile(); err != nil {
		return nil, err
	}

	return s, nil
}

// SaveEvent stores a raw eBPF event
func (s *Storage) SaveEvent(ctx context.Context, event *tracer.HTTPEvent) error {
	if !s.opts.SaveEvents {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if we need to rotate the file
	if s.eventsSize >= s.opts.MaxFileSize {
		if err := s.rotateEventsFile(); err != nil {
			return err
		}
	}

	// Write the event data
	var data []byte
	var err error

	if s.opts.RawFormat {
		// Write raw event data
		data = []byte(fmt.Sprintf("EVENT [%s] PID=%d TID=%d TYPE=%d SIZE=%d\n%s\n\n",
			time.Unix(0, int64(event.Timestamp)).Format(time.RFC3339Nano),
			event.PID,
			event.TID,
			event.Type,
			event.DataLen,
			string(event.Data[:event.DataLen]),
		))
	} else {
		// Write JSON-formatted event
		data, err = json.Marshal(event)
		if err != nil {
			return fmt.Errorf("marshaling event: %w", err)
		}
		data = append(data, '\n')
	}

	n, err := s.eventsFile.Write(data)
	if err != nil {
		return fmt.Errorf("writing event: %w", err)
	}

	s.eventsSize += int64(n)
	s.eventsCounter++

	return nil
}

// SaveTransaction stores a complete HTTP transaction
func (s *Storage) SaveTransaction(
	ctx context.Context,
	tx *storage.HTTPTransaction,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if we need to rotate the file
	if s.txSize >= s.opts.MaxFileSize {
		if err := s.rotateTxFile(); err != nil {
			return err
		}
	}

	// Write the transaction data
	var data []byte
	var err error

	if s.opts.RawFormat {
		// Write raw transaction data
		data = []byte(fmt.Sprintf("TRANSACTION [%s] -> [%s] (%s)\n"+
			"METHOD=%s URL=%s STATUS=%d\n"+
			"PROCESS=%s (PID=%d)\n"+
			"REQUEST (%d bytes):\n%s\n\n"+
			"RESPONSE (%d bytes):\n%s\n\n",
			tx.RequestTimestamp.Format(time.RFC3339Nano),
			tx.ResponseTimestamp.Format(time.RFC3339Nano),
			tx.Duration,
			tx.Method, tx.URL, tx.StatusCode,
			tx.ProcessName, tx.ProcessID,
			tx.RequestSize, tx.RequestData,
			tx.ResponseSize, tx.ResponseData,
		))
	} else {
		// Write JSON-formatted transaction
		data, err = json.Marshal(tx)
		if err != nil {
			return fmt.Errorf("marshaling transaction: %w", err)
		}
		data = append(data, '\n')
	}

	n, err := s.txFile.Write(data)
	if err != nil {
		return fmt.Errorf("writing transaction: %w", err)
	}

	s.txSize += int64(n)
	s.txCounter++

	return nil
}

// rotateEventsFile creates a new events file
func (s *Storage) rotateEventsFile() error {
	// Close existing file if open
	if s.eventsFile != nil {
		if err := s.eventsFile.Close(); err != nil {
			return fmt.Errorf("closing events file: %w", err)
		}
	}

	// Create a new file with timestamp
	fileName := fmt.Sprintf("%s-events-%s.%s",
		s.opts.Prefix,
		time.Now().Format("20060102-150405"),
		s.fileExtension(),
	)
	filePath := filepath.Join(s.opts.Directory, fileName)

	file, err := os.OpenFile(
		filePath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		s.opts.FileMode,
	)
	if err != nil {
		return fmt.Errorf("creating events file: %w", err)
	}

	s.eventsFile = file
	s.eventsSize = 0

	return nil
}

// rotateTxFile creates a new transactions file
func (s *Storage) rotateTxFile() error {
	// Close existing file if open
	if s.txFile != nil {
		if err := s.txFile.Close(); err != nil {
			return fmt.Errorf("closing transactions file: %w", err)
		}
	}

	// Create a new file with timestamp
	fileName := fmt.Sprintf("%s-transactions-%s.%s",
		s.opts.Prefix,
		time.Now().Format("20060102-150405"),
		s.fileExtension(),
	)
	filePath := filepath.Join(s.opts.Directory, fileName)

	file, err := os.OpenFile(
		filePath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		s.opts.FileMode,
	)
	if err != nil {
		return fmt.Errorf("creating transactions file: %w", err)
	}

	s.txFile = file
	s.txSize = 0

	return nil
}

// fileExtension returns the file extension based on the format
func (s *Storage) fileExtension() string {
	if s.opts.RawFormat {
		return "txt"
	}
	return "json"
}

// Close cleans up resources
func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err1, err2 error

	// Close events file if open
	if s.eventsFile != nil {
		err1 = s.eventsFile.Close()
		s.eventsFile = nil
	}

	// Close transactions file if open
	if s.txFile != nil {
		err2 = s.txFile.Close()
		s.txFile = nil
	}

	if err1 != nil {
		return err1
	}
	return err2
}
