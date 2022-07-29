package auth

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

// They have json names so that you
// can more easily read them from json
type GoGoogleCorpAuth struct {
	ClientID             string                                        `json:"client_id"`
	RedirectURL          string                                        `json:"redirect_url"`
	Domain               string                                        `json:"domain"`
	ClientSecret         string                                        `json:"client_secret"`
	DoDirectoryRequest   bool                                          `json:"do_directory_request"`
	Directories          []string                                      `json:"directories"`
	DirectoryCredentials security.GoGoogleCorpAuthDirectoryCredentials `json:"directory_creds"`
}

// Default returns "old" environment variable way
func Default() GoGoogleCorpAuth {
	return GoGoogleCorpAuth{
		ClientID:           os.Getenv("G_OAUTH_CLIENT"),
		RedirectURL:        os.Getenv("G_OAUTH_REDIRECT_URL"),
		Domain:             os.Getenv("G_OAUTH_DOMAIN"),
		ClientSecret:       os.Getenv("G_OAUTH_KEY"),
		DoDirectoryRequest: os.Getenv("G_OAUTH_DIRECTORY") != "",
		Directories:        strings.Split(os.Getenv("G_OAUTH_DIRECTORY"), ","),
		DirectoryCredentials: security.GoGoogleCorpAuthDirectoryCredentials{
			ServiceAccountMail:       os.Getenv("G_OAUTH_DIRECTORY_SA_EMAIL"),
			ServiceAccountPrivateKey: os.Getenv("G_OAUTH_DIRECTORY_PRIVATEKEY"),
			AdminAcccountMail:        os.Getenv("G_OAUTH_DIRECTORY_USER_EMAIL"),
		},
	}
}

func (i GoGoogleCorpAuth) StartOAuth(c *gin.Context) {
	c.Redirect(http.StatusFound, "https://accounts.google.com/o/oauth2/v2/auth?hd="+i.Domain+"&response_type=code&scope=email+profile+openid&redirect_uri="+i.RedirectURL+"&client_id="+i.ClientID)
}

type SuccessFunc func(c *gin.Context, user models.GoogleUser, hasOrgData bool, orgUser models.GoogleCorpUser)

func (i *GoGoogleCorpAuth) CompleteOAuth(c *gin.Context, callback SuccessFunc) {
	oauth_code := c.Query("code")
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"code":          {oauth_code},
		"client_id":     {i.ClientID},
		"client_secret": {i.ClientSecret},
		"redirect_uri":  {i.RedirectURL},
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
	if userData.Domain != i.Domain {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "Google account is not authorized to login!"})
		return
	}

	var userOrgData models.GoogleCorpUser
	hasOrgData := false
	if i.DoDirectoryRequest {
		serverAuth := security.ServerAuthToken(&i.DirectoryCredentials)
		reqd, _ := http.NewRequest("GET", "https://admin.googleapis.com/admin/directory/v1/users/"+userData.Email, nil)
		reqd.Header.Add("Authorization", "Bearer "+serverAuth.AccessToken)
		respd, errd := http.DefaultClient.Do(reqd)
		if errd != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "fail", "message": "Could not get Google directory response"})
			return
		}
		defer resp.Body.Close()
		responsed, errd := io.ReadAll(respd.Body)
		if respd.StatusCode != 200 {
			panic(string(responsed))
		}
		json.Unmarshal([]byte(responsed), &userOrgData)
		// Check if any path matches
		allowed := false
		for _, element := range i.Directories {
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
