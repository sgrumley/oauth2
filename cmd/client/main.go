// based off https://www.oauth.com/playground/
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

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

func main() {
	AuthorizationCodeFlow()
}

// https://authorization-server.com/authorize?
//	response_type=code
//	&client_id=oEGPvWefgcAyteDkBT4b2QSN
//	&redirect_uri=https://www.oauth.com/playground/authorization-code.html
//	&scope=photo+offline_access
//	&state=OqEo1LX_r-atq7-L

// TODO: needs work in terms of redirect and web pages...
func AuthorizationCodeFlow() {
	tls, err := NewSSLClient("server.crt")
	if err != nil {
		panic(err)
	}
	client := &AuthClient{
		ClientID:    "test_client",
		RedirectURI: "https://www.oauth.com/playground/authorization-code.html", // TODO:
		AuthURL:     "https://localhost:8443/authorize",
		TokenURL:    "https://localhost:8443/oauth/token",
		Client:      tls,
	}
	Step 1: Build the auth URL and redirect the user to the auth server
	authURL, state, err := client.BuildAuthorizationURL("posts read")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Redirect user to: %s\n", authURL)

		// Step 2: After the user is redirected back to the client, verify the state matches

		handleCallback := func(code, returnedState string) {
			token, err := client.ExchangeCodeForToken(code, returnedState, state)
			if err != nil {
				panic(err)
			}
			fmt.Printf("Access Token: %s\n", token.AccessToken)
		}

	handleCallback("returned_code", "returned_state")
	// Step 3: Exchange the auth code for an access token
}

func PKCEFlow() {
	// Step 1: Create a secret code verifier and code challenge

	// Step 2: Build the authorization URL and redirect the user to the auth server

	// Step 3: After the user is redirected back to the client, verify the state

	// Step 4: Exchange the auth code and code verifier for an access token
}

/*
https://authorization-server.com/authorize?

	response_type=token
	&client_id=oEGPvWefgcAyteDkBT4b2QSN
	&redirect_uri=https://www.oauth.com/playground/implicit.html
	&scope=photo
	&state=oex6wyIL6fRbLYcd
*/
func ImplicitFlow() {
	// Step 1: Build the auth URL and redirect the user to the auth server

	// Step 2: After the user is redirected back to the client, verify the state matches

	// Step 3: Exchange the access token from the URL fragment
}

func DeviceCodeFlow() {
	// Step 1: Request a device code from the auth server

	// Step 2: Instruct the user where to enter the code

	// Step 3: Poll the auth server periodically until the code has been successfully entered
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
