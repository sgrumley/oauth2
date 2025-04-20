# OAUTH2 Basic Implementation

## Overview
This project is for learning purposes only.
It is written with the internsion of deepening the understanding of the server side roles in different OAuth2 flows

There are many different flow to try out. Each one has a readme with instructions for how to run the demo
Services used: 
 - Mocked login page:8080
 - Client:8081 (callback endpoint)
 - Authorization Service:8082 (token, authorization, login... endpoints)

## Standards
- OAuth2
- OIDC OpenID Connect 
- Fapi2.0

## Flows
- Authorization Code 
- Implicit
- Device Code 
- PKCE

## Registration
Before any endpoints are hit. A `Client ID` and `Client Secret` must be provided to the client and store in this servers DB.
TODO: create an endpoint to generate this, it should also take information from the client (redirect_uri, name, ...)

## Requests
TODO: setup the cmd clients to read request data from yaml config

### Authorize
``` http
GET http://localhost:8080/oauth/authorize?
    response_type=code&
    client_id=test_client&
    redirect_uri=http://localhost:8081/callback
```

### Token
```http
POST http://localhost:8080/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code={code_from_step_1}&
client_id=test_client&
client_secret=test_secret&
redirect_uri=http://localhost:8081/callback
```

## References
Code is docmented with RFC references where applicable
- [oauth2 overview](https://auth0.com/intro-to-iam/what-is-oauth-2)
- [oauth2 deeper look](https://www.oauth.com/)
- [overview of all specs](https://www.oauth.com/oauth2-servers/map-oauth-2-0-specs/)
- [oauth2 - digitalocean guide](https://www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2)
- [oauth2 - authO spec](https://auth0.com/docs/authenticate/protocols/oauth#authorization-endpoint)
- [open id spec](https://openid.net/specs/openid-connect-core-1_0.html)
- [fapi 2.0 spec](https://oauth.net/fapi/)
- [mtls](https://www.securew2.com/blog/mutual-tls-mtls-authentication)
- [oauth2 specs](https://oauth.net/specs/)
- [oauth2 spec - rfc 6749](https://www.rfc-editor.org/rfc/rfc6749)
- [oauth2 spec bearer token - rfc 6750](https://www.rfc-editor.org/rfc/rfc6750)
- [oauth2 spec Token Introspection - rfc 7662](https://www.rfc-editor.org/rfc/rfc7662)
