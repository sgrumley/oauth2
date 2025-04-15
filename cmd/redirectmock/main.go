package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type OAuthConfig struct {
	ClientID     string
	RedirectURI  string
	AuthEndpoint string
}

// Default configuration
var config = OAuthConfig{
	ClientID:    "client-id",
	RedirectURI: "http://localhost:8081/callback",
}

// Handler for the main page - shows login form
func handleHome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, homeHTML)
}

// Handler for processing the login form submission
func handleSubmitLogin(w http.ResponseWriter, r *http.Request) {
	fmt.Println("[Mock Login] submit logged")
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get query parameters from the referrer URL
	referrer := r.Header.Get("Referer")
	var state string
	var redirectURI string

	if referrer != "" {
		refURL, err := url.Parse(referrer)
		if err == nil {
			// Extract the state parameter from the referrer URL
			state = refURL.Query().Get("state")
			redirectURI = refURL.Query().Get("redirect_uri")
		}
	}

	// Parse the form to get username/password
	err := r.ParseForm()
	if err != nil {
		fmt.Fprintf(w, errorHTML, "Error parsing form data")
		return
	}

	// Get username and password from the form
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	// In a real application, you would validate the credentials here
	// For this demo, we'll just consider it a success if they provided any credentials
	if username == "" || password == "" {
		fmt.Fprintf(w, errorHTML, "Username and password are required")
		return
	}

	// Build the callback URL
	callbackURL := "http://localhost:8081/callback"
	if redirectURI != "" {
		callbackURL = redirectURI
	}

	// Add the state parameter if it exists
	if state != "" {
		if strings.Contains(callbackURL, "?") {
			callbackURL += "&state=" + url.QueryEscape(state)
		} else {
			callbackURL += "?state=" + url.QueryEscape(state)
		}
	}

	// Redirect to the callback URL
	fmt.Println("[Mock Login] Redirected to " + callbackURL)
	http.Redirect(w, r, callbackURL, http.StatusFound)
}

// Handler for the login page - shows login form
func handleLogin(w http.ResponseWriter, r *http.Request) {
	// Store the query parameters in the session or use them directly
	fmt.Fprintf(w, homeHTML)
}

func main() {
	// Register route handlers
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/submit-login", handleSubmitLogin)

	// Start the server
	port := ":8080"
	fmt.Printf("Login Demo started at http://localhost%s\n", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
