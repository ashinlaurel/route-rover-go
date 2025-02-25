package controllers

import (
	"context"
	"route-rover-go/database"
	"route-rover-go/models"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var userCollection = database.GetCollection("users")

// Register User
func RegisterUser(c *fiber.Ctx) error {
	var user models.User
	if err := c.BodyParser(&user); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	user.ID = primitive.NewObjectID()
	_, err := userCollection.InsertOne(context.TODO(), user)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Could not create user"})
	}

	return c.JSON(user)
}

// Get All Users
func GetUsers(c *fiber.Ctx) error {
	var users []models.User
	cursor, err := userCollection.Find(context.TODO(), bson.M{})
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch users"})
	}

	defer cursor.Close(context.TODO())
	for cursor.Next(context.TODO()) {
		var user models.User
		cursor.Decode(&user)
		users = append(users, user)
	}

	return c.JSON(users)
}
