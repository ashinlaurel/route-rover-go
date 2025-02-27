package controllers

import (
	"context"
	"log"
	"route-rover-go/database"
	"route-rover-go/models"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func RegisterUser(db *database.DatabaseHandler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var user models.User
		if err := c.BodyParser(&user); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		user.ID = primitive.NewObjectID()
		_, err := db.UserCollection.InsertOne(context.TODO(), user)
		if err != nil {
			log.Fatal("errorrrr")
			return c.Status(500).JSON(fiber.Map{"error": "Could not create user"})
		}

		return c.JSON(user)
	}
}
