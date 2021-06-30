package main

import (
	goauth "github.com/factorycampus/go-google-corp-auth/controllers"
	gdata "github.com/factorycampus/go-google-corp-auth/models"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	r.GET("/g-oauth/", goauth.StartOAuth)
	r.GET("/g-oauth/complete", func(c *gin.Context) {
		goauth.CompleteOAuth(c, func(c *gin.Context, userData gdata.GoogleUser) {
			c.JSON(200, gin.H{
				"message":   "Logged in!",
				"givenName": userData.GivenName,
				"lastName":  userData.FamilyName,
				"email":     userData.Email,
			})
		})
	})

	r.Run()
}
