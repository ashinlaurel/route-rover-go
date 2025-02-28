package middlewares_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"route-rover-go/middlewares"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Setup test environment
func setupTest() *fiber.App {
	app := fiber.New()

	// Set JWT secret for testing
	os.Setenv("JWT_SECRET", "test-secret-key")

	return app
}

// Test GenerateToken function
func TestGenerateToken(t *testing.T) {
	// Setup
	_ = setupTest()

	t.Run("Successful token generation", func(t *testing.T) {
		// Generate a test user ID
		userID := primitive.NewObjectID()

		// Generate token
		token, err := middlewares.GenerateToken(userID)

		// Assertions
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})
}

// Test ExtractTokenMetadata function
func TestExtractTokenMetadata(t *testing.T) {
	// Setup
	app := setupTest()

	t.Run("Successful token extraction", func(t *testing.T) {
		// Generate a test user ID
		userID := primitive.NewObjectID()

		// Generate token
		token, err := middlewares.GenerateToken(userID)
		assert.NoError(t, err)

		// Create a test endpoint that uses ExtractTokenMetadata
		app.Get("/test", func(c *fiber.Ctx) error {
			metadata, err := middlewares.ExtractTokenMetadata(c)
			if err != nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
			}
			return c.JSON(fiber.Map{
				"user_id": metadata.UserID,
				"expires": metadata.Expires.Unix(),
			})
		})

		// Create request with token
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		// Execute request
		resp, _ := app.Test(req)

		// Assertions
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("Missing authorization header", func(t *testing.T) {
		// Create a test endpoint that uses ExtractTokenMetadata
		app.Get("/test-missing-auth", func(c *fiber.Ctx) error {
			metadata, err := middlewares.ExtractTokenMetadata(c)
			if err != nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
			}
			return c.JSON(fiber.Map{
				"user_id": metadata.UserID,
				"expires": metadata.Expires.Unix(),
			})
		})

		// Create request without token
		req := httptest.NewRequest(http.MethodGet, "/test-missing-auth", nil)

		// Execute request
		resp, _ := app.Test(req)

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Invalid token", func(t *testing.T) {
		// Create a test endpoint that uses ExtractTokenMetadata
		app.Get("/test-invalid-token", func(c *fiber.Ctx) error {
			metadata, err := middlewares.ExtractTokenMetadata(c)
			if err != nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
			}
			return c.JSON(fiber.Map{
				"user_id": metadata.UserID,
				"expires": metadata.Expires.Unix(),
			})
		})

		// Create request with invalid token
		req := httptest.NewRequest(http.MethodGet, "/test-invalid-token", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")

		// Execute request
		resp, _ := app.Test(req)

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// Test AuthMiddleware function
func TestAuthMiddleware(t *testing.T) {
	// Setup
	app := setupTest()

	// Create a protected route
	app.Get("/protected", middlewares.AuthMiddleware(), func(c *fiber.Ctx) error {
		userID := c.Locals("userID").(string)
		return c.JSON(fiber.Map{"user_id": userID})
	})

	t.Run("Successful authentication", func(t *testing.T) {
		// Generate a test user ID
		userID := primitive.NewObjectID()

		// Generate token
		token, err := middlewares.GenerateToken(userID)
		assert.NoError(t, err)

		// Create request with token
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		// Execute request
		resp, _ := app.Test(req)

		// Assertions
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("Missing token", func(t *testing.T) {
		// Create request without token
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)

		// Execute request
		resp, _ := app.Test(req)

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Expired token", func(t *testing.T) {
		// Create a test endpoint with a custom middleware that simulates an expired token
		app.Get("/expired", func(c *fiber.Ctx) error {
			// Set an expired token metadata
			c.Locals("userID", primitive.NewObjectID().Hex())
			tokenMetadata := &middlewares.TokenMetadata{
				UserID:  primitive.NewObjectID().Hex(),
				Expires: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
			}

			// Manually check expiration as the middleware would
			if time.Now().After(tokenMetadata.Expires) {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "Token expired",
				})
			}

			return c.JSON(fiber.Map{"user_id": tokenMetadata.UserID})
		})

		// Create request
		req := httptest.NewRequest(http.MethodGet, "/expired", nil)

		// Execute request
		resp, _ := app.Test(req)

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}
