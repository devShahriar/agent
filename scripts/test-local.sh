#!/bin/bash

# Start Quickwit
echo "Starting Quickwit..."
docker-compose up -d

# Wait for Quickwit to be ready
echo "Waiting for Quickwit to be ready..."
sleep 5

# Create Kafka topic for HTTP events (if not already created)
echo "Creating Kafka topic..."
docker run --network host confluentinc/cp-kafka:latest kafka-topics.sh --create --topic http-events --bootstrap-server localhost:9094 --partitions 1 --replication-factor 1

# Build and run the API server
echo "Building and running API server..."
cd cmd/api
go build -o api-server
./api-server &
API_PID=$!

# Test the API server
echo "Testing API server..."
curl -X POST http://localhost:8080/events -H "Content-Type: application/json" -d '[
  {
    "timestamp": "2024-03-20T10:00:00Z",
    "pid": 1234,
    "tid": 5678,
    "process_name": "test-process",
    "command": "test-command",
    "type": 1,
    "data_len": 10,
    "conn_id": "test-conn",
    "data": "test data"
  }
]'

# Wait for data to be processed
echo "Waiting for data to be processed..."
sleep 5

# Check Quickwit for the data
echo "Checking Quickwit for the data..."
curl -X GET http://localhost:7280/api/v1/search?query=test-process

# Cleanup
echo "Cleaning up..."
kill $API_PID
cd ../..
docker-compose down

echo "Local testing completed!" 