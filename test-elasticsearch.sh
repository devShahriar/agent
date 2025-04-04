#!/bin/bash
set -e

echo "Testing ABProxy agent with existing Elasticsearch deployment..."

# Set Elasticsearch URL to match the existing service in the monitoring namespace
ES_URL=${ES_URL:-"http://elasticsearch-service.monitoring.svc.cluster.local:9200"}
ES_INDEX=${ES_INDEX:-"abproxy"}

# Function to make test requests
make_test_requests() {
  echo "Making test HTTP requests with uniquetest123 header..."
  
  # GET request
  curl -s -H "X-Custom-Header: uniquetest123" \
    http://go-test-server:8080/get?param1=value1&param2=value2 > /dev/null
  
  # POST request with JSON
  curl -s -X POST -H "Content-Type: application/json" -H "X-Custom-Header: uniquetest123" \
    -d '{"name":"test","value":"data"}' \
    http://go-test-server:8080/post > /dev/null
    
  echo "Test requests completed."
}

# Function to check Elasticsearch for data
check_elasticsearch() {
  echo "Checking Elasticsearch for captured HTTP transactions..."
  
  # Wait a few seconds for data to be processed
  sleep 5
  
  # Query Elasticsearch for data with our uniquetest123 header
  RESULT=$(curl -s -X GET "$ES_URL/$ES_INDEX-http-transactions-*/_search?q=uniquetest123" | jq .)
  
  # Check if we got any hits
  HITS=$(echo $RESULT | jq '.hits.hits | length')
  
  if [ "$HITS" -gt 0 ]; then
    echo "Success! Found $HITS HTTP transactions in Elasticsearch."
    echo "Sample transaction:"
    echo $RESULT | jq '.hits.hits[0]._source' | jq '.'
    return 0
  else
    echo "No HTTP transactions found in Elasticsearch. Check agent configuration."
    return 1
  fi
}

# Make test requests
make_test_requests

# Check Elasticsearch
check_elasticsearch

echo "Test completed." 