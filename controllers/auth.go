package controllers

import (
	"io"
	"os"
	"strings"

	"encoding/json"

	"net/http"
	"net/url"

	"github.com/factorycampus/go-google-corp-auth/models"
	"github.com/factorycampus/go-google-corp-auth/security"

	"github.com/gin-gonic/gin"
)

func StartOAuth(c *gin.Context) {
	clientId := os.Getenv("G_OAUTH_CLIENT")
	redirectUrl := os.Getenv("G_OAUTH_REDIRECT_URL")
	hd := os.Getenv("G_OAUTH_DOMAIN")
	c.Redirect(http.StatusFound, "https://accounts.google.com/o/oauth2/v2/auth?hd="+hd+"&response_type=code&scope=email+profile+openid&redirect_uri="+redirectUrl+"&client_id="+clientId)
}

type SuccessFunc func(c *gin.Context, user models.GoogleUser, hasOrgData bool, orgUser models.GoogleCorpUser)

func CompleteOAuth(c *gin.Context, callback SuccessFunc) {
	oauth_code := c.Query("code")
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"code":          {oauth_code},
		"client_id":     {os.Getenv("G_OAUTH_CLIENT")},
		"client_secret": {os.Getenv("G_OAUTH_KEY")},
		"redirect_uri":  {os.Getenv("G_OAUTH_REDIRECT_URL")},
		"grant_type":    {"authorization_code"},
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "Authoriziation failed!"})
		return
	}
	if resp.StatusCode != 200 {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "Google did not verify the data!"})
		return
	}
	defer resp.Body.Close()
	var loginData models.GoogleResponse
	response, err := io.ReadAll(resp.Body)
	json.Unmarshal([]byte(response), &loginData)

	// Double check mail
	req, err := http.NewRequest("GET", "https://openidconnect.googleapis.com/v1/userinfo", nil)
	req.Header.Add("Authorization", "Bearer "+loginData.AccessToken)
	mailResp, mailErr := http.DefaultClient.Do(req)
	if mailErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "fail", "message": "Could not get Google mail response"})
		return
	}
	defer resp.Body.Close()
	mailResponse, mailErr := io.ReadAll(mailResp.Body)
	var userData models.GoogleUser
	json.Unmarshal([]byte(mailResponse), &userData)
	if userData.Domain != os.Getenv("G_OAUTH_DOMAIN") {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "Google account is not authorized to login!"})
		return
	}

	var userOrgData models.GoogleCorpUser
	hasOrgData := false
	if os.Getenv("G_OAUTH_DIRECTORY") != "" {
		serverAuth := security.ServerAuthToken()
		reqd, _ := http.NewRequest("GET", "https://admin.googleapis.com/admin/directory/v1/users/"+userData.Email, nil)
		reqd.Header.Add("Authorization", "Bearer "+serverAuth.AccessToken)
		respd, errd := http.DefaultClient.Do(reqd)
		if errd != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "fail", "message": "Could not get Google directory response"})
			return
		}
		defer resp.Body.Close()
		responsed, errd := io.ReadAll(respd.Body)
		json.Unmarshal([]byte(responsed), &userOrgData)
		// Check if any path matches
		allowed := false
		for _, element := range strings.Split(os.Getenv("G_OAUTH_DIRECTORY"), ",") {
			if element == userOrgData.Directory {
				allowed = true
			}
		}
		if !allowed {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "Access Denied"})
			return
		}

		hasOrgData = true
	}

	// We verified the user being allowed to login
	// Now pass it back to have the app handle
	// the specific login
	callback(c, userData, hasOrgData, userOrgData)
}
