package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

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

	// Set up logging
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{
		// Add timestamp formatting
		TimestampFormat: time.RFC3339,
		// Add caller information to help with debugging
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			filename := path.Base(f.File)
			return fmt.Sprintf("%s()", f.Function), fmt.Sprintf("%s:%d", filename, f.Line)
		},
	})

	// Set log level
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		log.WithError(err).Warn("Invalid log level, defaulting to info")
		level = logrus.InfoLevel
	}
	log.SetLevel(level)

	// Create storage
	var storage tracer.Storage
	if *storageType == "file" {
		storage, err = tracer.NewFileStorage(*fileDir)
		if err != nil {
			log.WithError(err).Fatal("Failed to create file storage")
		}
	} else if *storageType == "elasticsearch" {
		storage, err = tracer.NewElasticsearchStorage(*esURL, *esPrefix)
		if err != nil {
			log.WithError(err).Fatal("Failed to create Elasticsearch storage")
		}
	} else {
		log.Fatal("Invalid storage type")
	}
	defer storage.Close()

	// Create tracer
	t, err := tracer.NewTracer(log, storage, nil)
	if err != nil {
		log.WithError(err).Fatal("Failed to create tracer")
	}

	// Set up event callback
	t.SetEventCallback(func(event tracer.HTTPEvent) {
		// Add debug logging to see what traffic is being received
		log.WithFields(logrus.Fields{
			"pid":          event.PID,
			"process_name": event.ProcessName,
			"command":      event.Command,
			"method":       event.Method,
			"url":          event.URL,
		}).Debug("Received event before filtering")

		// Filter well-known Kubernetes processes only
		isK8s := false
		k8sProcesses := []string{
			"kubelet",
			"kube-proxy",
			"coredns",
			"etcd",
			"kube-apiserver",
		}
		for _, proc := range k8sProcesses {
			if strings.Contains(strings.ToLower(event.ProcessName), proc) {
				isK8s = true
				break
			}
		}

		if isK8s {
			log.WithField("process", event.ProcessName).
				Debug("Skipping Kubernetes system process")
			return
		}

		// Skip only obvious health check endpoints
		if event.URL != "" && (strings.Contains(strings.ToLower(event.URL), "/healthz") ||
			strings.Contains(strings.ToLower(event.URL), "/health") ||
			strings.Contains(strings.ToLower(event.URL), "/ready") ||
			strings.Contains(strings.ToLower(event.URL), "/metrics")) {
			log.WithField("url", event.URL).Debug("Skipping health check endpoint")
			return
		}

		// Format the HTTP data for human-readable output
		formattedData := tracer.FormatHTTPData(&event)

		// Log event summary for all applications with formatted HTTP data
		log.WithFields(logrus.Fields{
			"type":         event.Type,
			"pid":          event.PID,
			"process_name": event.ProcessName,
			"method":       event.Method,
			"url":          event.URL,
			"status_code":  event.StatusCode,
			"http_data":    formattedData,
		}).Info("HTTP event received")
	})

	// Start tracer
	if err := t.Start(); err != nil {
		log.WithError(err).Fatal("Failed to start tracer")
	}

	// Wait for interrupt
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	// Stop tracer
	t.Stop()
	log.Info("Tracer stopped")
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
