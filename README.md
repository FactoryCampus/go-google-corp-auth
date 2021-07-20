# GO Google Corp Auth
Uses Google Social Auth in a Go Gin app to authorize a login in an corporate environment.

## Usage
Call "controllers.StartOAuth" and "controllers.CompleteOAuth" in the gin handlers.
You can find the implementation details in [the example](https://github.com/FactoryCampus/go-google-corp-auth/blob/main/example/example.go).

Set the following environment variables.
- G_OAUTH_CLIENT: Client for OAuth
- G_OAUTH_KEY: Key for OAuth
- G_OAUTH_REDIRECT_URL: URL to redirect to after Google OAuth. This should be your complete handler
- G_OAUTH_DOMAIN: Domain of the Google domain
For verifying that the user is in a specific group:
- G_OAUTH_DIRECTORY: Organizational unit to allow access to (multiple options seperated by ,)
- G_OAUTH_DIRECTORY_PRIVATEKEY: Private key for service account (base64 encoded)
- G_OAUTH_DIRECTORY_SA_EMAIL: Email of service account
- G_OAUTH_DIRECTORY_USER_EMAIL: Email of admin user
