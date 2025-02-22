package main

import (
	"html/template"
	"net/http"
	"path/filepath"
)

type AuthHandler struct {
	templates *template.Template
	client    *AuthClient
}

type PageData struct {
	ClientID    string
	RedirectURI string
	State       string
	Code        string
	Error       string
}

func NewAuthHandler(templatesDir string, client *AuthClient) (*AuthHandler, error) {
	// Load all templates from the templates directory
	templates, err := template.ParseGlob(filepath.Join(templatesDir, "*.html"))
	if err != nil {
		return nil, err
	}

	return &AuthHandler{
		templates: templates,
		client:    client,
	}, nil
}

func (h *AuthHandler) HandleAuth(w http.ResponseWriter, r *http.Request) {
	// Generate authorization URL and state
	authURL, state, err := h.client.BuildAuthorizationURL("your_scope")
	if err != nil {
		http.Error(w, "Failed to build auth URL", http.StatusInternalServerError)
		return
	}

	data := PageData{
		ClientID:    h.client.ClientID,
		RedirectURI: h.client.RedirectURI,
		State:       state,
	}

	// Render the auth template
	err = h.templates.ExecuteTemplate(w, "auth.html", data)
	if err != nil {
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
		return
	}
}

func (h *AuthHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	data := PageData{
		Code:  code,
		State: state,
	}

	if code == "" {
		data.Error = "No authorization code received"
	}

	// Render the callback template
	err := h.templates.ExecuteTemplate(w, "callback.html", data)
	if err != nil {
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
		return
	}
}

// Example usage in main.go:
func main() {
	client, err := NewAuthClient(
		"your_client_id",
		"your_client_secret",
		"https://localhost:8443/callback",
		"https://auth-server.com/authorize",
		"https://auth-server.com/token",
		"server.crt",
	)
	if err != nil {
		panic(err)
	}

	handler, err := NewAuthHandler("templates", client)
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/auth", handler.HandleAuth)
	http.HandleFunc("/callback", handler.HandleCallback)

	// Start the server...
}
