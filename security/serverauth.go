package security

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"

	"github.com/factorycampus/go-google-corp-auth/models"
	"github.com/golang-jwt/jwt"

	"time"
)

type GoGoogleCorpAuthDirectoryCredentials struct {
	ServiceAccountMail       string      `json:"sa_mail"`
	ServiceAccountPrivateKey string      `json:"sa_priv_key"`
	AdminAcccountMail        string      `json:"admin_mail"`
	loginCache               *LoginCache `json:"-"`
}

type LoginCache struct {
	currentLogin *models.GoogleResponse
	invalidTime  time.Time
}

func ServerAuthToken(c *GoGoogleCorpAuthDirectoryCredentials) models.GoogleResponse {
	if c.loginCache == nil || c.loginCache.invalidTime.Before(time.Now()) {
		c.loginCache = &LoginCache{}
		token := createJWT(*c)
		login := doAuthRequest(token)
		c.loginCache.currentLogin = &login
		c.loginCache.invalidTime = time.Now().Add(time.Duration((c.loginCache.currentLogin.ExpiresIn - 60)) * time.Second)
	}
	return *c.loginCache.currentLogin
}

func createJWT(c GoGoogleCorpAuthDirectoryCredentials) string {
	start := time.Now().Unix()
	end := time.Now().Unix() + (60 * 60)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   c.ServiceAccountMail,
		"scope": "https://www.googleapis.com/auth/admin.directory.user.readonly",
		"aud":   "https://oauth2.googleapis.com/token",
		"sub":   c.AdminAcccountMail,
		"exp":   end,
		"iat":   start,
	})

	// Sign and get the complete encoded token as a string using the secret
	_privKeyPem, err := base64.StdEncoding.DecodeString(c.ServiceAccountPrivateKey)
	if err != nil {
		print("[G-O Auth] Error while decoding private key")
		print(string(err.Error()))
	}
	pem, _ := pem.Decode(_privKeyPem)
	key, err := x509.ParsePKCS8PrivateKey(pem.Bytes)
	if err != nil {
		print("[G-O Auth] Error while reading PEM")
		print(string(err.Error()))
	}
	tokenString, err1 := token.SignedString(key)
	if err1 != nil {
		print("[G-O Auth] Error while signing JWT")
		print(string(err1.Error()))
	}
	return tokenString
}

func doAuthRequest(jwt string) models.GoogleResponse {
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {jwt},
	})
	if err != nil {
		panic("[G-O Auth] Could not connect to Google for Server Token")
	}
	if resp.StatusCode != 200 {
		panic("[G-O Auth] Could not login to Google with Server Token")
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	var loginData models.GoogleResponse
	json.Unmarshal([]byte(response), &loginData)
	println("[G-O Auth] Logged In Service Account")
	return loginData
}
