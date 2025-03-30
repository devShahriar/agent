package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	// Handle root path
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request: %s %s", r.Method, r.URL.Path)
		fmt.Fprintf(w, "Hello from test server!")
	})

	// Handle a POST endpoint
	http.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read body
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		log.Printf("Received POST data: %s", string(buf[:n]))

		// Send response
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status": "ok", "message": "Data received"}`)
	})

	// Start server
	port := ":8000"
	log.Printf("Starting test server on port %s", port)
	if err := http.ListenAndServeTLS(port, "test/testserver/cert.pem", "test/testserver/key.pem", nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
