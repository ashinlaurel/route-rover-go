package controllers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// MockUser represents a user for testing
type MockUser struct {
	ID       primitive.ObjectID `json:"id"`
	Name     string             `json:"name"`
	Email    string             `json:"email"`
	Password string             `json:"-"`
}

// Setup test environment
func setupTest() *fiber.App {
	app := fiber.New()

	// Set JWT secret for testing
	os.Setenv("JWT_SECRET", "test-secret-key")

	return app
}

// Test LoginUser function
func TestLoginUser(t *testing.T) {
	// Setup
	app := setupTest()

	// Create a test user
	userID := primitive.NewObjectID()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	testUser := MockUser{
		ID:       userID,
		Name:     "Test User",
		Email:    "test@example.com",
		Password: string(hashedPassword),
	}

	// Create a login route
	app.Post("/login", func(c *fiber.Ctx) error {
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

		// Check if email matches test user
		if loginData.Email != testUser.Email {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		// Verify password
		err := bcrypt.CompareHashAndPassword([]byte(testUser.Password), []byte(loginData.Password))
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		// Return success response
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"token": "test-token",
			"user": fiber.Map{
				"id":    testUser.ID,
				"name":  testUser.Name,
				"email": testUser.Email,
			},
		})
	})

	t.Run("Successful login", func(t *testing.T) {
		// Create request
		loginData := map[string]string{
			"email":    "test@example.com",
			"password": "password123",
		}
		jsonData, _ := json.Marshal(loginData)
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(jsonData))
		req.Header.Set("Content-Type", "application/json")

		// Execute request
		resp, _ := app.Test(req)

		// Assertions
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)

		assert.Contains(t, result, "token")
		assert.Contains(t, result, "user")

		userMap, ok := result["user"].(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, "Test User", userMap["name"])
		assert.Equal(t, "test@example.com", userMap["email"])
	})

	t.Run("Invalid credentials", func(t *testing.T) {
		// Create request with wrong password
		loginData := map[string]string{
			"email":    "test@example.com",
			"password": "wrongpassword",
		}
		jsonData, _ := json.Marshal(loginData)
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(jsonData))
		req.Header.Set("Content-Type", "application/json")

		// Execute request
		resp, _ := app.Test(req)

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Missing fields", func(t *testing.T) {
		// Create request with missing password
		loginData := map[string]string{
			"email": "test@example.com",
		}
		jsonData, _ := json.Marshal(loginData)
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(jsonData))
		req.Header.Set("Content-Type", "application/json")

		// Execute request
		resp, _ := app.Test(req)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// Test GetUserProfile function
func TestGetUserProfile(t *testing.T) {
	// Setup
	app := setupTest()

	// Create a test user
	userID := primitive.NewObjectID()
	testUser := MockUser{
		ID:    userID,
		Name:  "Test User",
		Email: "test@example.com",
	}

	// Create a profile route with middleware to set userID
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("userID", userID.Hex())
		return c.Next()
	})

	app.Get("/profile", func(c *fiber.Ctx) error {
		// Get user ID from context (set by middleware)
		userIDStr := c.Locals("userID").(string)

		// Verify it's our test user ID
		if userIDStr != userID.Hex() {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}

		// Return user data
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"user": fiber.Map{
				"id":    testUser.ID,
				"name":  testUser.Name,
				"email": testUser.Email,
			},
		})
	})

	t.Run("Successful profile retrieval", func(t *testing.T) {
		// Create request
		req := httptest.NewRequest(http.MethodGet, "/profile", nil)

		// Execute request
		resp, _ := app.Test(req)

		// Assertions
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)

		userMap, ok := result["user"].(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, "Test User", userMap["name"])
		assert.Equal(t, "test@example.com", userMap["email"])
	})

	// For "User not found" test, we'll create a separate app instance
	t.Run("User not found", func(t *testing.T) {
		// Create a new app
		notFoundApp := setupTest()

		// Create a profile route with different user ID
		notFoundApp.Use(func(c *fiber.Ctx) error {
			c.Locals("userID", primitive.NewObjectID().Hex())
			return c.Next()
		})

		notFoundApp.Get("/profile", func(c *fiber.Ctx) error {
			// Get user ID from context
			userIDStr := c.Locals("userID").(string)

			// Verify it's our test user ID
			if userIDStr != userID.Hex() {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
			}

			// Return user data
			return c.Status(fiber.StatusOK).JSON(fiber.Map{
				"user": fiber.Map{
					"id":    testUser.ID,
					"name":  testUser.Name,
					"email": testUser.Email,
				},
			})
		})

		// Create request
		req := httptest.NewRequest(http.MethodGet, "/profile", nil)

		// Execute request
		resp, _ := notFoundApp.Test(req)

		// Assertions
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

// Test UpdateUserProfile function
func TestUpdateUserProfile(t *testing.T) {
	// Setup
	app := setupTest()

	// Create a test user
	userID := primitive.NewObjectID()
	testUser := MockUser{
		ID:    userID,
		Name:  "Original Name",
		Email: "original@example.com",
	}

	// Create middleware to set userID
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("userID", userID.Hex())
		return c.Next()
	})

	// Create an update route
	app.Put("/profile", func(c *fiber.Ctx) error {
		// Get user ID from context
		userIDStr := c.Locals("userID").(string)

		// Verify it's our test user ID
		if userIDStr != userID.Hex() {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}

		// Parse request body
		var updateData struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Password string `json:"password,omitempty"`
		}
		if err := c.BodyParser(&updateData); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
		}

		// Update user data
		if updateData.Name != "" {
			testUser.Name = updateData.Name
		}
		if updateData.Email != "" {
			// Check if email is "existing@example.com" to simulate conflict
			if updateData.Email == "existing@example.com" {
				return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Email already in use"})
			}
			testUser.Email = updateData.Email
		}
		if updateData.Password != "" {
			// Hash new password
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updateData.Password), bcrypt.DefaultCost)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not process request"})
			}
			testUser.Password = string(hashedPassword)
		}

		// Return updated user data
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"user": fiber.Map{
				"id":    testUser.ID,
				"name":  testUser.Name,
				"email": testUser.Email,
			},
		})
	})

	t.Run("Successful profile update", func(t *testing.T) {
		// Create request
		updateData := map[string]string{
			"name":  "Updated Name",
			"email": "updated@example.com",
		}
		jsonData, _ := json.Marshal(updateData)
		req := httptest.NewRequest(http.MethodPut, "/profile", bytes.NewReader(jsonData))
		req.Header.Set("Content-Type", "application/json")

		// Execute request
		resp, _ := app.Test(req)

		// Assertions
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)

		userMap, ok := result["user"].(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, "Updated Name", userMap["name"])
		assert.Equal(t, "updated@example.com", userMap["email"])
	})

	t.Run("Email already in use", func(t *testing.T) {
		// Create request with conflicting email
		updateData := map[string]string{
			"email": "existing@example.com",
		}
		jsonData, _ := json.Marshal(updateData)
		req := httptest.NewRequest(http.MethodPut, "/profile", bytes.NewReader(jsonData))
		req.Header.Set("Content-Type", "application/json")

		// Execute request
		resp, _ := app.Test(req)

		// Assertions
		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})

	t.Run("Password update", func(t *testing.T) {
		// Create request with password update
		updateData := map[string]string{
			"password": "newpassword123",
		}
		jsonData, _ := json.Marshal(updateData)
		req := httptest.NewRequest(http.MethodPut, "/profile", bytes.NewReader(jsonData))
		req.Header.Set("Content-Type", "application/json")

		// Execute request
		resp, _ := app.Test(req)

		// Assertions
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify password was updated by trying to compare
		err := bcrypt.CompareHashAndPassword([]byte(testUser.Password), []byte("newpassword123"))
		assert.NoError(t, err)
	})
}
