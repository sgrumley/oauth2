package authcode

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// callback is an endpoint to capture that the login was a success and signals the /auth endpoint to redirect the user
func Callback(w http.ResponseWriter, r *http.Request) {
	fmt.Println("[Server] Callback Received")
	// code := r.URL.Query().Get("code")
	// state := r.URL.Query().Get("state")

	// Check for errors in the callback
	// if errMsg := r.URL.Query().Get("error"); errMsg != "" {
	// 	errDesc := r.URL.Query().Get("error_description")
	// 	fmt.Fprintf(w, errMsg, errDesc)
	// 	return
	// }

	fmt.Fprintf(w,
		r.URL.String(),
	)

	fmt.Println("[Server] Callback - channel sent")
	go func() {
		successChan <- true
	}()
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents the JSON response sent back to the frontend
type LoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers to allow requests from any origin (for development)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight OPTIONS request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Only accept POST requests
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode the JSON request
	var loginReq LoginRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&loginReq); err != nil {
		sendJSONResponse(w, false, "Invalid request format", http.StatusBadRequest)
		return
	}

	// if loginReq.Username == "admin" && loginReq.Password == "password123" {
	sendJSONResponse(w, true, "Login successful", http.StatusOK)
	// } else {
	// sendJSONResponse(w, false, "Invalid username or password", http.StatusUnauthorized)
	// }
}

// dupe func
func sendJSONResponse(w http.ResponseWriter, success bool, message string, statusCode int) {
	// Create the response
	response := LoginResponse{
		Success: success,
		Message: message,
	}

	// Set content type header
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	// Encode and send the response
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(response); err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
	}
}
