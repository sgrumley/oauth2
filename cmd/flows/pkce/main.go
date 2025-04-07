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

	go PKCEFlow()

	fmt.Println("[Client] listening on localhost" + port)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func PKCEFlow() {
	// Step 1: Create a secret code verifier and code challenge

	// Step 2: Build the authorization URL and redirect the user to the auth server

	// Step 3: After the user is redirected back to the client, verify the state

	// Step 4: Exchange the auth code and code verifier for an access token
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
