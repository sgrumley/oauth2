package main

import (
	"fmt"
	"log"
	"net/http"
)

var port = ":8081"

func main() {
	mux := http.NewServeMux()

	// Routes
	mux.HandleFunc("GET /callback", callback)
	mux.HandleFunc("POST /callback", callback)

	server := &http.Server{
		Addr:    port,
		Handler: mux,
	}

	go DeviceCodeFlow()

	fmt.Println("[Client] listening on localhost" + port)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func DeviceCodeFlow() {
	// Step 1: Request a device code from the auth server

	// Step 2: Instruct the user where to enter the code

	// Step 3: Poll the auth server periodically until the code has been successfully entered
}

// TODO: move to pkg
func callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Check for errors in the callback
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		fmt.Fprintf(w, errMsg, errDesc)
		return
	}

	// In a real implementation, validate state to prevent CSRF attacks
	if state == "" {
		http.Error(w, "Missing state parameter", http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w,
		r.URL.String(),
		code,
		state,
	)
}
