package config

import (
	"log"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	GoogleOAuthConfig *oauth2.Config
)

func InitOAuthConfig() {
	clientID := os.Getenv("GOOGLE_WEB_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	redirectURL := os.Getenv("GOOGLE_REDIRECT_URL")

	log.Printf("OAuth Config - ClientID: %s, RedirectURL: %s", clientID, redirectURL)

	if clientID == "" || clientSecret == "" || redirectURL == "" {
		log.Fatal("Missing required OAuth configuration. Please check your .env file")
	}

	GoogleOAuthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}
