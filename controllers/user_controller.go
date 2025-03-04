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

func UpdateUserProfile(db *database.DatabaseHandler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get user ID from context
		userIDStr := c.Locals("userID").(string)
		userID, err := primitive.ObjectIDFromHex(userIDStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
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

		// Create update document
		update := bson.M{}
		if updateData.Name != "" {
			update["name"] = updateData.Name
		}
		if updateData.Email != "" {
			// Check if email is already taken
			if updateData.Email != "" {
				var existingUser models.User
				err := db.UserCollection.FindOne(context.TODO(), bson.M{
					"email": updateData.Email,
					"_id":   bson.M{"$ne": userID},
				}).Decode(&existingUser)
				if err == nil {
					return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Email already in use"})
				}
			}
			update["email"] = updateData.Email
		}
		if updateData.Password != "" {
			// Hash new password
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updateData.Password), bcrypt.DefaultCost)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not process request"})
			}
			update["password"] = string(hashedPassword)
		}

		// Update user in database
		if len(update) > 0 {
			_, err = db.UserCollection.UpdateOne(
				context.TODO(),
				bson.M{"_id": userID},
				bson.M{"$set": update},
			)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not update user"})
			}
		}

		// Fetch updated user data
		var updatedUser models.User
		err = db.UserCollection.FindOne(context.TODO(), bson.M{"_id": userID}).Decode(&updatedUser)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not retrieve updated user"})
		}

		// Return updated user data
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"user": fiber.Map{
				"id":    updatedUser.ID,
				"name":  updatedUser.Name,
				"email": updatedUser.Email,
			},
		})
	}
}