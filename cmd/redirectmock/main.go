package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
)

// Configuration for our OAuth client
type OAuthConfig struct {
	ClientID     string
	RedirectURI  string
	AuthEndpoint string
}

// Default configuration
// Config should come from url query params not from this struct
var config = OAuthConfig{
	ClientID: "client-id",
	// RedirectURI: "http://localhost:8080/callback",
	RedirectURI: "http://localhost:8081/callback",
	// AuthEndpoint: "http://auth-server.com/authorize",
}

// Handler for the main page - shows login button
func handleHome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, homeHTML)
}

// Handler for initiating the OAuth flow
func handleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate a random state parameter to mitigate CSRF attacks
	state := "xyz123" // In a real implementation, use a secure random generator

	// Build the authorization URL
	authURL, err := url.Parse(config.AuthEndpoint)
	if err != nil {
		http.Error(w, "Invalid auth endpoint URL", http.StatusInternalServerError)
		return
	}

	query := authURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", config.ClientID)
	query.Set("redirect_uri", config.RedirectURI)
	query.Set("state", state)
	query.Set("scope", "profile email")
	authURL.RawQuery = query.Encode()

	// Redirect to the authorization server
	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// Handler for the OAuth callback
func handleCallback(w http.ResponseWriter, r *http.Request) {
	fmt.Println("[Resource Mock] received call")
	// Get the authorization code and state from the URL
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Check for errors in the callback
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		fmt.Fprintf(w, callbackErrorHTML, errMsg, errDesc)
		return
	}

	// In a real implementation, validate state to prevent CSRF attacks
	if state == "" {
		http.Error(w, "Missing state parameter", http.StatusBadRequest)
		return
	}

	// Display the callback data
	fmt.Fprintf(w, callbackSuccessHTML,
		r.URL.String(),
		code,
		state,
	)
}

func main() {
	// Register route handlers
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)

	// Start the server
	port := ":8080"
	fmt.Printf("OAuth Redirect Demo started at http://localhost%s\n", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
