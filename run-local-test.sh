#!/bin/bash
set -e

# Run the test server in the background
echo "Starting local test server..."

# Check if Go is installed
if command -v go &> /dev/null; then
    go run cmd/test-server/main.go &
    SERVER_PID=$!
    echo "Test server started with PID: $SERVER_PID"
else
    echo "Go is not installed. Please install Go or use the Docker version."
    exit 1
fi

# Wait for server to start
echo "Waiting for server to start..."
sleep 2

# Function to make requests
make_requests() {
    # GET request
    echo -e "\nMaking GET request with uniquetest123 header..."
    curl -s -H "X-Custom-Header: uniquetest123" http://localhost:8080/get?param1=value1&param2=value2

    # POST request with JSON body
    echo -e "\n\nMaking POST request with uniquetest123 header..."
    curl -s -X POST \
      -H "Content-Type: application/json" \
      -H "X-Custom-Header: uniquetest123" \
      -d '{"name":"test","value":"data"}' \
      http://localhost:8080/post

    # PUT request
    echo -e "\n\nMaking PUT request with uniquetest123 header..."
    curl -s -X PUT \
      -H "Content-Type: application/json" \
      -H "X-Custom-Header: uniquetest123" \
      -d '{"name":"updated","value":"newdata"}' \
      http://localhost:8080/put

    echo -e "\n"
}

# Run requests in a loop
echo "Starting test client to make requests..."
for i in {1..3}; do
    echo -e "\n--- Request set $i ---"
    make_requests
    sleep 2
done

# Cleanup
echo -e "\nStopping test server..."
kill $SERVER_PID
echo "Done." 