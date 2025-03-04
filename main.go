package main

import (
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"

	"route-rover-go/config"
	"route-rover-go/database"
	"route-rover-go/routes"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Initialize database
	db, err := database.NewDatabase()
	if err != nil {
		log.Fatal("Database connection failed:", err)
	}
	// defer db.Client.Disconnect(nil)

	// Initialize OAuth configuration
	config.InitOAuthConfig()

	// Create Fiber app
	app := fiber.New()

	// Routes
	routes.AuthRoutes(app, db)
	routes.UserRoutes(app, db)

	// Start server
	fmt.Println("Server is running on port 8080")
	app.Listen(":8080")
}
