package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// TODO: move to pkg
func NewSSLClient(serverCertPath string) (*http.Client, error) {
	// Load the self-signed certificate
	serverCert, err := os.ReadFile(serverCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	// Create a certificate pool and add the server certificate
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(serverCert) {
		return nil, fmt.Errorf("failed to add server certificate to pool")
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}

	// Create HTTP client with TLS configuration
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}, nil
}

var (
	port         = ":8081"
	authCodeChan = make(chan string)
	stateChan    = make(chan string)
)

func main() {
	mux := http.NewServeMux()

	// Routes
	mux.HandleFunc("GET /callback", callback)
	mux.HandleFunc("POST /callback", callback)

	server := &http.Server{
		Addr:    port,
		Handler: mux,
	}

	go AuthorizationCodeFlow()

	fmt.Println("[Client] listening on localhost" + port)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

// https://authorization-server.com/authorize?
//	response_type=code
//	&client_id=oEGPvWefgcAyteDkBT4b2QSN
//	&redirect_uri=https://www.oauth.com/playground/authorization-code.html
//	&scope=photo+offline_access
//	&state=OqEo1LX_r-atq7-L

func AuthorizationCodeFlow() {
	fmt.Println("[Client] Started auth flow")
	// tls, err := NewSSLClient("server.crt")
	// if err != nil {
	// 	panic(err)
	// }
	cli := &http.Client{
		Timeout: 3 * time.Second,
	}
	client := &AuthClient{
		ClientID: "test_client",
		// NOTE: remember to put https back
		RedirectURI: "http://localhost:8081/callback",
		AuthURL:     "http://localhost:8082/authorize",
		TokenURL:    "http://localhost:8082/oauth/token",
		// Client:      tls,
		Client: cli,
	}
	// Step 1: Build the auth URL and redirect the user to the auth server
	authURL, state, err := client.BuildAuthorizationURL("posts read")
	if err != nil {
		panic(err)
	}
	// fmt.Printf("Redirect user to: %s\n", authURL)

	// Step 2: Make auth code request
	fmt.Println("[Client] Calling " + authURL)
	err = client.GetAuthCode()
	if err != nil {
		panic(err)
	}

	fmt.Println("[Client] Waiting for authorization code")
	// TODO: look for a better way to do this? A way to get the correct authcode if called multiple times?
	authCode := <-authCodeChan
	returnedState := <-stateChan
	fmt.Printf("[Client] Auth Code: %s\n", authCode)

	// Step 3: After the user is redirected back to the client, verify the state matches
	handleCallback := func(code, returnedState string) {
		fmt.Println("[Client] Calling /token")
		token, err := client.ExchangeCodeForToken(code, returnedState, state)
		if err != nil {
			panic(err)
		}
		fmt.Printf("[Client] Completed flow with Access Token: %s\n", token.AccessToken)
	}

	handleCallback(authCode, returnedState)
	// Step 3: Exchange the auth code for an access token
}

// TODO: move to pkg if it can be reused by other flows
func callback(w http.ResponseWriter, r *http.Request) {
	fmt.Println("[Client] Callback Received")
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

	fmt.Println("[Client] Callback - channel sent")
	go func() {
		authCodeChan <- code
		stateChan <- state
	}()
}
