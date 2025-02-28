package controllers

import (
	"context"
	"log"
	"route-rover-go/database"
	"route-rover-go/middlewares"
	"route-rover-go/models"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// RegisterUser handles user registration
func RegisterUser(db *database.DatabaseHandler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var user models.User
		if err := c.BodyParser(&user); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
		}

		// Validate input
		if user.Email == "" || user.Password == "" || user.Name == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Name, email and password are required"})
		}

		// Check if user already exists
		var existingUser models.User
		err := db.UserCollection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&existingUser)
		if err == nil {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "User with this email already exists"})
		}

		// Hash password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Println("Error hashing password:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not process request"})
		}
		user.Password = string(hashedPassword)

		// Create user in database
		user.ID = primitive.NewObjectID()
		_, err = db.UserCollection.InsertOne(context.TODO(), user)
		if err != nil {
			log.Println("Error creating user:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not create user"})
		}

		// Generate JWT token
		token, err := middlewares.GenerateToken(user.ID)
		if err != nil {
			log.Println("Error generating token:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate token"})
		}

		// Return token and user info (excluding password)
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"token": token,
			"user": fiber.Map{
				"id":    user.ID,
				"name":  user.Name,
				"email": user.Email,
			},
		})
	}
}

// LoginUser handles user authentication

