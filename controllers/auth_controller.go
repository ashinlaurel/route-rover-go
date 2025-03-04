package controllers

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"route-rover-go/config"
	"route-rover-go/database"
	"route-rover-go/middlewares"
	"route-rover-go/models"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

func LoginUser(db *database.DatabaseHandler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Parse request body
		var loginData struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := c.BodyParser(&loginData); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
		}

		// Validate input
		if loginData.Email == "" || loginData.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Email and password are required"})
		}

		// Check if user exists
		var user models.User
		err := db.UserCollection.FindOne(context.TODO(), bson.M{"email": loginData.Email}).Decode(&user)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		// Verify password
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password))
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		// Generate JWT token
		token, err := middlewares.GenerateToken(user.ID)
		if err != nil {
			log.Println("Error generating token:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate token"})
		}

		// Return token and user info
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"token": token,
			"user": fiber.Map{
				"id":    user.ID,
				"name":  user.Name,
				"email": user.Email,
			},
		})
	}
}

// GetUserProfile returns the user profile
func GetUserProfile(db *database.DatabaseHandler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get user ID from context (set by AuthMiddleware)
		userIDStr := c.Locals("userID").(string)
		userID, err := primitive.ObjectIDFromHex(userIDStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
		}

		// Fetch user data from database
		var user models.User
		err = db.UserCollection.FindOne(context.TODO(), bson.M{"_id": userID}).Decode(&user)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}

		// Return user data (excluding sensitive information)
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"user": fiber.Map{
				"id":    user.ID,
				"name":  user.Name,
				"email": user.Email,
			},
		})
	}
}

// GoogleLogin initiates the Google OAuth flow
func GoogleLogin(db *database.DatabaseHandler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Generate random state
		state := "random-state" // In production, use a secure random string
		c.Cookie(&fiber.Cookie{
			Name:     "oauth_state",
			Value:    state,
			HTTPOnly: true,
		})

		// Redirect to Google's consent page
		url := config.GoogleOAuthConfig.AuthCodeURL(state)
		return c.Redirect(url)
	}
}

// GoogleCallback handles the OAuth callback from Google
func GoogleCallback(db *database.DatabaseHandler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Verify state
		state := c.Cookies("oauth_state")
		if state == "" || state != c.Query("state") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid state"})
		}

		// Get authorization code
		code := c.Query("code")
		if code == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Code not found"})
		}

		// Exchange code for token
		token, err := config.GoogleOAuthConfig.Exchange(context.Background(), code)
		if err != nil {
			log.Printf("Error exchanging code for token: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to exchange token"})
		}

		// Get user info from Google
		userInfo, err := getUserInfoFromGoogle(token)
		if err != nil {
			log.Printf("Error getting user info: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to get user info"})
		}

		// Check if user exists
		var user models.User
		err = db.UserCollection.FindOne(context.TODO(), bson.M{
			"$or": []bson.M{
				{"email": userInfo.Email},
				{"google_id": userInfo.ID},
			},
		}).Decode(&user)

		if err != nil {
			// User doesn't exist, create new user
			user = models.User{
				ID:             primitive.NewObjectID(),
				Name:           userInfo.Name,
				Email:          userInfo.Email,
				GoogleID:       userInfo.ID,
				AuthProvider:   "google",
				ProfilePicture: userInfo.Picture,
			}
			_, err = db.UserCollection.InsertOne(context.TODO(), user)
			if err != nil {
				log.Printf("Error creating user: %v", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create user"})
			}
		} else if user.GoogleID == "" {
			// User exists but hasn't linked Google account
			_, err = db.UserCollection.UpdateOne(
				context.TODO(),
				bson.M{"_id": user.ID},
				bson.M{
					"$set": bson.M{
						"google_id":       userInfo.ID,
						"auth_provider":   "google",
						"profile_picture": userInfo.Picture,
					},
				},
			)
			if err != nil {
				log.Printf("Error updating user: %v", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update user"})
			}
		}

		// Generate JWT token
		tokenString, err := middlewares.GenerateToken(user.ID)
		if err != nil {
			log.Printf("Error generating token: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate token"})
		}

		// Return token and user info
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"token": tokenString,
			"user": fiber.Map{
				"id":              user.ID,
				"name":            user.Name,
				"email":           user.Email,
				"auth_provider":   user.AuthProvider,
				"profile_picture": user.ProfilePicture,
			},
		})
	}
}

// GoogleUserInfo represents the user info from Google
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

func getUserInfoFromGoogle(token *oauth2.Token) (*GoogleUserInfo, error) {
	client := config.GoogleOAuthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userInfo GoogleUserInfo
	if err := json.Unmarshal(data, &userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}
