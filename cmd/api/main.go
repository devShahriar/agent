package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/segmentio/kafka-go"
)

type Config struct {
	Port        string
	KafkaBroker string
	KafkaTopic  string
}

func main() {
	// Load configuration
	config := Config{
		Port:        getEnv("PORT", "8001"),
		KafkaBroker: getEnv("KAFKA_BROKER", "localhost:9094"),
		KafkaTopic:  getEnv("KAFKA_TOPIC", "http-events"),
	}

	// Initialize Kafka writer
	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers:  []string{config.KafkaBroker},
		Topic:    config.KafkaTopic,
		Balancer: &kafka.LeastBytes{},
		Logger: kafka.LoggerFunc(func(msg string, args ...interface{}) {
			log.Printf("Kafka: "+msg, args...)
		}),
	})
	defer writer.Close()

	// Create router
	router := gin.Default()

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Events endpoint
	router.POST("/events", func(c *gin.Context) {
		var events []map[string]interface{}
		if err := c.ShouldBindJSON(&events); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Forward events to Kafka
		for _, event := range events {
			data, err := json.Marshal(event)
			if err != nil {
				log.Printf("Failed to marshal event: %v", err)
				continue
			}

			err = writer.WriteMessages(context.Background(),
				kafka.Message{
					Value: data,
				},
			)
			if err != nil {
				log.Printf("Failed to write message to Kafka: %v", err)
			}
		}

		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Transactions endpoint
	router.POST("/transactions", func(c *gin.Context) {
		var transactions []map[string]interface{}
		if err := c.ShouldBindJSON(&transactions); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Forward transactions to Kafka
		for _, tx := range transactions {
			data, err := json.Marshal(tx)
			if err != nil {
				log.Printf("Failed to marshal transaction: %v", err)
				continue
			}

			err = writer.WriteMessages(context.Background(),
				kafka.Message{
					Value: data,
				},
			)
			if err != nil {
				log.Printf("Failed to write message to Kafka: %v", err)
			}
		}

		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Start server
	srv := &http.Server{
		Addr:    ":" + config.Port,
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
