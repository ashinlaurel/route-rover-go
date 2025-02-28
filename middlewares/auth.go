package middlewares

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// TokenMetadata contains the claims data
type TokenMetadata struct {
	UserID  string
	Expires time.Time
}

// GenerateToken creates a new JWT token for a user
func GenerateToken(userID primitive.ObjectID) (string, error) {
	// Get the JWT secret from environment variable
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "your-secret-key" // Default secret (should be changed in production)
	}

	// Create token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set claims
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = userID.Hex()
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix() // Token expires in 72 hours

	// Generate encoded token
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ExtractTokenMetadata extracts the token metadata from the request
func ExtractTokenMetadata(c *fiber.Ctx) (*TokenMetadata, error) {
	// Get the JWT secret from environment variable
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "your-secret-key" // Default secret (should be changed in production)
	}

	// Get token from Authorization header
	tokenString := c.Get("Authorization")
	if tokenString == "" {
		return nil, fmt.Errorf("authorization header is required")
	}

	// Remove Bearer prefix
	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)

	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Get user ID
	userID, ok := claims["user_id"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid user id")
	}

	// Get expiration time
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid expiration time")
	}

	// Create token metadata
	tokenMetadata := &TokenMetadata{
		UserID:  userID,
		Expires: time.Unix(int64(exp), 0),
	}

	return tokenMetadata, nil
}

// AuthMiddleware is a middleware to check if user is authenticated
func AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Extract token metadata
		tokenMetadata, err := ExtractTokenMetadata(c)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Unauthorized",
			})
		}

		// Check if token is expired
		if time.Now().After(tokenMetadata.Expires) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Token expired",
			})
		}

		// Set user ID in context
		c.Locals("userID", tokenMetadata.UserID)

		return c.Next()
	}
}
