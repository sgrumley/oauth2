package main

type Response struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

// https://auth0.com/docs/authenticate/protocols/oauth#token-endpoint
// func token(c echo.Context) error {
// 	return c.String(http.StatusOK, "Hello, World!")
// }

type AuthRequest struct {
	// Tells the authorization server which grant to execute.
	ResponseType string `json:"response_type"`
	//   (Optional) How the result of the authorization request is formatted. Values:
	// - query: for Authorization Code grant. 302 Found triggers redirect.
	// - fragment: for Implicit grant. 302 Found triggers redirect.
	// - form_post: 200 OK with response parameters embedded in an HTML form as hidden parameters.
	// - web_message: For Silent Authentication. Uses HTML5 web messaging.
	ResponseMode string `json:"response_mode"`
	// The ID of the application that asks for authorization.
	ClientID string `json:"client_id"`
	// Holds a URL. A successful response from this endpoint results in a redirect to this URL.
	RedirectURI string `json:"redirect_uri"`
	// A space-delimited list of permissions that the application requires.
	Scope []string `json:"scope"`
	// An opaque value, used for security purposes. If this request parameter is set in the request, then it is returned to the application as part of the redirect_uri.
	State string `json:"state"`
	// Specifies the connection type for Passwordless connections
	Connection string `json:"connection"`
}

// https://auth0.com/docs/authenticate/protocols/oauth#authorization-endpoint
// func authorization(c echo.Context) error {
// 	response := Response{
// 		Message: "This is a JSON response",
// 		Status:  "success",
// 	}
// 	return c.JSON(http.StatusOK, response)
// }
