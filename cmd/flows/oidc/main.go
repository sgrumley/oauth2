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

	go OpenIDConnectFlow()

	fmt.Println("[Client] listening on localhost" + port)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

/*
https://authorization-server.com/authorize?

	response_type=code
	&client_id=oEGPvWefgcAyteDkBT4b2QSN
	&redirect_uri=https://www.oauth.com/playground/oidc.html
	&scope=openid+profile+email+photos
	&state=bMhQFrbmARcNCMD9
	&nonce=ztxRXu5lP2DMA2fi
*/
func OpenIDConnectFlow() {
	// Step 1: Build the auth URL and redirect the user to the auth server

	// Step 2: After the user is redirected back to the client, verify the state matches

	// Step 3: Exchange the auth code for an ID token and access token
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
