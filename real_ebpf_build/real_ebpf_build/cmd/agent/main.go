package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"abproxy/pkg/storage"
	"abproxy/pkg/storage/elasticsearch"
	"abproxy/pkg/storage/file"
	"abproxy/pkg/tracer"
)

var (
	// Configuration flags
	logLevel = flag.String(
		"log-level",
		"info",
		"Log level (debug, info, warn, error)",
	)
	storageType   = flag.String("storage", "file", "Storage type (file, elasticsearch)")
	fileDir       = flag.String("file-dir", "./data", "Directory for file storage")
	filePrefix    = flag.String("file-prefix", "http-traffic", "Prefix for file storage")
	fileRawFormat = flag.Bool(
		"file-raw",
		false,
		"Use raw format for file storage (instead of JSON)",
	)
	saveEvents = flag.Bool(
		"save-events",
		false,
		"Save individual events in addition to transactions",
	)
	esURL = flag.String(
		"es-url",
		"http://elasticsearch:9200",
		"Elasticsearch URL",
	)
	esAuth = flag.String(
		"es-auth",
		"",
		"Elasticsearch basic auth (username:password)",
	)
	esPrefix = flag.String("es-prefix", "abproxy", "Elasticsearch index prefix")
)

var log = logrus.New()

func init() {
	log.SetFormatter(&logrus.JSONFormatter{})
}

func main() {
	// Parse flags
	flag.Parse()

	// Set log level
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		log.WithError(err).Fatal("Invalid log level")
	}
	log.SetLevel(level)

	log.Info("Starting HTTP traffic tracer...")

	// Create context that will be canceled on shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create storage
	var store storage.Storage
	switch *storageType {
	case "file":
		fileOpts := file.Options{
			Directory:   *fileDir,
			Prefix:      *filePrefix,
			SaveEvents:  *saveEvents,
			RawFormat:   *fileRawFormat,
			MaxFileSize: 100 * 1024 * 1024, // 100MB
			FileMode:    0644,
		}
		store, err = file.New(fileOpts)
		if err != nil {
			log.WithError(err).Fatal("Failed to create file storage")
		}
	case "elasticsearch":
		esOpts := elasticsearch.Options{
			URL:         *esURL,
			BasicAuth:   *esAuth,
			IndexPrefix: *esPrefix,
			SaveEvents:  *saveEvents,
			BatchSize:   1000,
		}
		store, err = elasticsearch.New(esOpts)
		if err != nil {
			log.WithError(err).Fatal("Failed to create Elasticsearch storage")
		}
	default:
		log.Fatalf("Unknown storage type: %s", *storageType)
	}
	defer store.Close()

	// Create storage manager
	storageManager := storage.NewManager(store, nil)
	defer storageManager.Close()

	// Create tracer
	t, err := tracer.NewTracer(log, func(event tracer.HTTPEvent) {
		// Log summary of the event
		logEvent(&event)

		// Save the event to storage
		if err := storageManager.ProcessEvent(ctx, &event); err != nil {
			log.WithError(err).Error("Failed to process event")
		}
	})
	if err != nil {
		log.WithError(err).Fatal("Failed to create tracer")
	}
	defer t.Close()

	// Start tracer
	if err := t.Start(); err != nil {
		log.WithError(err).Fatal("Failed to start tracer")
	}

	log.Info("Tracer is running. Press Ctrl+C to stop.")

	// Start a cleanup routine for old connections
	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()

	go func() {
		for {
			select {
			case <-cleanupTicker.C:
				storageManager.CleanupOldConnections(5 * time.Minute)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Info("Shutting down tracer...")
}

// logEvent logs a summary of the HTTP event
func logEvent(event *tracer.HTTPEvent) {
	// Create structured record
	eventType := "response"
	if event.Type == tracer.EventTypeSSLWrite {
		eventType = "request"
	}

	// Create basic record
	record := map[string]interface{}{
		"timestamp":    time.Unix(0, int64(event.Timestamp)),
		"pid":          event.PID,
		"process_name": event.ProcessName,
		"type":         eventType,
	}

	// Add HTTP-specific fields
	if event.Type == tracer.EventTypeSSLWrite && event.Method != "" {
		record["method"] = event.Method
		record["url"] = event.URL
	} else if event.Type == tracer.EventTypeSSLRead {
		record["status_code"] = event.StatusCode
		record["content_type"] = event.ContentType
	}

	jsonData, err := json.Marshal(record)
	if err != nil {
		log.WithError(err).Error("Failed to marshal event data")
		return
	}

	log.Info(string(jsonData))
}
