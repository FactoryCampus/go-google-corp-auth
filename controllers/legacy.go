package controllers

// This exists to not break old code
// Look at the example for the new
// type of implementation

import (
	gauth "github.com/factorycampus/go-google-corp-auth/auth"

	"github.com/gin-gonic/gin"
)

var instance gauth.GoGoogleCorpAuth

func StartOAuth(c *gin.Context) {
	if instance.ClientID == "" {
		instance = gauth.Default()
	}
	instance.StartOAuth(c)
}

func CompleteOAuth(c *gin.Context, callback gauth.SuccessFunc) {
	if instance.ClientID == "" {
		instance = gauth.Default()
	}
	instance.CompleteOAuth(c, callback)
}
