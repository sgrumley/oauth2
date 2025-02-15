// based off https://www.oauth.com/playground/
package main

func main() {
}

/*
https://authorization-server.com/authorize?

	response_type=code
	&client_id=oEGPvWefgcAyteDkBT4b2QSN
	&redirect_uri=https://www.oauth.com/playground/authorization-code.html
	&scope=photo+offline_access
	&state=OqEo1LX_r-atq7-L
*/
func AuthorizationCodeFlow() {
	// Step 1: Build the auth URL and redirect the user to the auth server

	// Step 2: After the user is redirected back to the client, verify the state matches

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
