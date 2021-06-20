# GO Google Corp Auth
Uses Google Social Auth in a Go Gin app to authorize a login in an corporate environment.

## Usage
Call "controllers.StartOAuth" and "controllers.CompleteOAuth" in the gin handlers.
Set the following environment variables.
- G_OAUTH_CLIENT
- G_OAUTH_KEY
- G_OAUTH_REDIRECT_URL
- G_OAUTH_DOMAIN