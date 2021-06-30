package security

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/factorycampus/go-google-corp-auth/models"
	"github.com/golang-jwt/jwt"

	"time"
)

func ServerAuthToken() models.GoogleResponse {
	token := createJWT()
	return doAuthRequest(token)
}

func createJWT() string {
	start := time.Now().Unix()
	end := time.Now().Unix() + (60 * 60)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   os.Getenv("G_OAUTH_DIRECTORY_SA_EMAIL"),
		"scope": "https://www.googleapis.com/auth/admin.directory.user.readonly",
		"aud":   "https://oauth2.googleapis.com/token",
		"sub":   os.Getenv("G_OAUTH_DIRECTORY_USER_EMAIL"),
		"exp":   end,
		"iat":   start,
	})

	// Sign and get the complete encoded token as a string using the secret
	_privKeyPem, _ := base64.StdEncoding.DecodeString(os.Getenv("G_OAUTH_DIRECTORY_PRIVATEKEY"))
	pem, _ := pem.Decode(_privKeyPem)
	key, err := x509.ParsePKCS8PrivateKey(pem.Bytes)
	if err != nil {
		print("Error while reading PEM")
		print(string(err.Error()))
	}
	tokenString, err1 := token.SignedString(key)
	if err1 != nil {
		print("Error while signing JWT")
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
		panic("Could not connect to Google for Server Token")
	}
	if resp.StatusCode != 200 {
		panic("Could not login to Google with Server Token")
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	var loginData models.GoogleResponse
	json.Unmarshal([]byte(response), &loginData)
	return loginData
}
