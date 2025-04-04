package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	// Set up routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/get", getHandler)
	http.HandleFunc("/post", postHandler)
	http.HandleFunc("/put", putHandler)
	http.HandleFunc("/delete", deleteHandler)
	http.HandleFunc("/status/", statusCodeHandler)
	http.HandleFunc("/headers", headersHandler)
	http.HandleFunc("/delay/", delayHandler)
	http.HandleFunc("/stream/", streamHandler)
	http.HandleFunc("/health", healthHandler)

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Start server
	addr := fmt.Sprintf(":%s", port)
	log.Printf("Starting test server on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	endpoints := map[string]string{
		"/":         "This help message",
		"/get":      "Returns GET data",
		"/post":     "Returns POST data",
		"/put":      "Returns PUT data",
		"/delete":   "Returns DELETE data",
		"/status/n": "Returns response with status code n",
		"/headers":  "Returns request headers",
		"/delay/n":  "Delays response by n seconds",
		"/stream/n": "Streams n lines of data",
		"/health":   "Health check endpoint",
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"endpoints": endpoints,
		"info":      "Test server for HTTP traffic monitoring",
		"version":   "1.0.0",
	})
}

func getHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Test-Header", "test-value")

	resp := map[string]interface{}{
		"method":    r.Method,
		"url":       r.URL.String(),
		"headers":   getHeadersMap(r),
		"args":      r.URL.Query(),
		"timestamp": time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(resp)
}

func postHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Test-Header", "test-value")

	resp := map[string]interface{}{
		"method":    r.Method,
		"url":       r.URL.String(),
		"headers":   getHeadersMap(r),
		"data":      string(body),
		"timestamp": time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(resp)
}

func putHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"method":    r.Method,
		"url":       r.URL.String(),
		"headers":   getHeadersMap(r),
		"data":      string(body),
		"timestamp": time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(resp)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"method":    r.Method,
		"url":       r.URL.String(),
		"headers":   getHeadersMap(r),
		"timestamp": time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(resp)
}

func statusCodeHandler(w http.ResponseWriter, r *http.Request) {
	var statusCode int
	_, err := fmt.Sscanf(r.URL.Path, "/status/%d", &statusCode)
	if err != nil || statusCode < 100 || statusCode > 599 {
		http.Error(
			w,
			"Invalid status code. Use a number between 100-599",
			http.StatusBadRequest,
		)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := map[string]interface{}{
		"code":      statusCode,
		"message":   http.StatusText(statusCode),
		"timestamp": time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(resp)
}

func headersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Test-Response-Header", "test-response-value")

	resp := map[string]interface{}{
		"headers": getHeadersMap(r),
	}

	json.NewEncoder(w).Encode(resp)
}

func delayHandler(w http.ResponseWriter, r *http.Request) {
	var delaySeconds int
	_, err := fmt.Sscanf(r.URL.Path, "/delay/%d", &delaySeconds)
	if err != nil || delaySeconds < 0 || delaySeconds > 10 {
		http.Error(
			w,
			"Invalid delay value. Use a number between 0-10",
			http.StatusBadRequest,
		)
		return
	}

	time.Sleep(time.Duration(delaySeconds) * time.Second)

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"delay":     delaySeconds,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(resp)
}

func streamHandler(w http.ResponseWriter, r *http.Request) {
	var lines int
	_, err := fmt.Sscanf(r.URL.Path, "/stream/%d", &lines)
	if err != nil || lines < 1 || lines > 100 {
		http.Error(
			w,
			"Invalid stream count. Use a number between 1-100",
			http.StatusBadRequest,
		)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Transfer-Encoding", "chunked")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	for i := 0; i < lines; i++ {
		data := map[string]interface{}{
			"line":      i + 1,
			"total":     lines,
			"timestamp": time.Now().Format(time.RFC3339),
		}

		jsonData, _ := json.Marshal(data)
		fmt.Fprintf(w, "%s\n", jsonData)
		flusher.Flush()
		time.Sleep(200 * time.Millisecond)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	resp := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(resp)
}

func getHeadersMap(r *http.Request) map[string]string {
	headers := make(map[string]string)
	for name, values := range r.Header {
		headers[name] = values[0]
	}
	return headers
}
