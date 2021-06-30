package models

type GoogleResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	IdToken     string `json:"id_token"`
}

type GoogleUser struct {
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Locale        string `json:"locale"`
	Domain        string `json:"hd"`
}

// Not all are implemented
type GoogleCorpUser struct {
	Id                    string `json:"id"`
	CustomerId            string `json:"customerId"`
	Directory             string `json:"orgUnitPath"`
	IsAdmin               bool   `json:"isAdmin"`
	ChangePasswordAtLogin bool   `json:"changePasswordAtNextLogin"`
}
