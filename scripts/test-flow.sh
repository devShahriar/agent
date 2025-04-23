#!/bin/bash

# Start Quickwit
echo "Starting Quickwit..."
docker-compose up -d

# Wait for Quickwit to be ready
echo "Waiting for Quickwit to be ready..."
sleep 10

# Create Kafka topic for HTTP events (if not already created)
echo "Creating Kafka topic..."
CMD='docker run --network host automqinc/automq:latest /bin/bash -c "/opt/kafka/kafka/bin/kafka-topics.sh --create --topic http-events --bootstrap-server localhost:9094 --partitions 1 --replication-factor 1"'; [ "$(uname)" = "Linux" ] && eval "sudo $CMD" || eval $CMD

# Start API server
echo "Starting API server..."
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

# Wait a moment for the message to be produced
echo "Waiting for message to be produced..."
sleep 2

# Check topic offsets to see if messages were produced
echo "Checking topic offsets..."
CMD='docker run --network automq_net automqinc/automq:latest /bin/bash -c "/opt/kafka/kafka/bin/kafka-topics.sh --describe --topic http-events --bootstrap-server broker1:9092,broker2:9092"'; [ "$(uname)" = "Linux" ] && eval "sudo $CMD" || eval $CMD

# Verify data in AutoMQ
echo "Verifying data in AutoMQ..."
CMD='docker run --network host automqinc/automq:latest /bin/bash -c "/opt/kafka/kafka/bin/kafka-console-consumer.sh --topic http-events --from-beginning --bootstrap-server localhost:9094 --property print.key=true --property key.separator=: --timeout-ms 5000"'; [ "$(uname)" = "Linux" ] && eval "sudo $CMD" || eval $CMD

# Wait for data to be processed by Quickwit
echo "Waiting for data to be processed by Quickwit..."
sleep 5

# Check Quickwit for the data
echo "Checking Quickwit for the data..."
curl -X GET http://localhost:7280/api/v1/search?query=test-process

# Cleanup
echo "Cleaning up..."
kill $API_PID
cd ../..
docker-compose down

echo "Testing completed!" 