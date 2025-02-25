package main

import (
	"github.com/gofiber/fiber/v2"
	"route-rover-go/config"
	"route-rover-go/database"
	"route-rover-go/routes"
)

func main() {
	config.LoadEnv()
	database.ConnectDB()

	app := fiber.New()

	routes.UserRoutes(app)

	app.Listen(":8080")
}
