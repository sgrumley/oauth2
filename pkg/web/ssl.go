package web

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

func GetDefaultConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}
