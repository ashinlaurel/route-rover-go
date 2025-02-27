package main

import (
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"

	"route-rover-go/database"
	"route-rover-go/routes"
)

func main() {
	// Initialize database
	db, err := database.NewDatabase()
	if err != nil {
		log.Fatal("Database connection failed:", err)
	}
	// defer db.Client.Disconnect(nil)

	// Create Fiber app
	app := fiber.New()

	// Routes
	routes.UserRoutes(app, db)

	// Start server
	fmt.Println("Server is running on port 8080")
	app.Listen(":8080")
}
