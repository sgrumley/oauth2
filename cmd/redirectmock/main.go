package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
)

type TemplateData struct {
	CSS template.CSS
	JS  template.JS
}

// type OAuthConfig struct {
// 	ClientID     string
// 	RedirectURI  string
// 	AuthEndpoint string
// }
//
// // Default configuration
// var config = OAuthConfig{
// 	ClientID:    "client-id",
// 	RedirectURI: "http://localhost:8081/callback",
// }

func main() {
	// Register route handlers
	http.HandleFunc("/", RenderLogin)
	http.HandleFunc("/login", RenderLogin)

	// Start the server
	port := ":8080"
	fmt.Printf("Login Demo started at http://localhost%s\n", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
