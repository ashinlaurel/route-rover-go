package routes

import (
	"route-rover-go/controllers"
	"route-rover-go/database"

	"route-rover-go/middlewares"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

// AuthRoutes defines the authentication routes
func AuthRoutes(app *fiber.App, db *database.DatabaseHandler) {
	// Create a group for auth routes with logger middleware
	auth := app.Group("/api/auth", logger.New())

	// Register routes
	auth.Post("/login", controllers.LoginUser(db))
	auth.Get("/profile", middlewares.AuthMiddleware(), controllers.GetUserProfile(db))
	auth.Put("/profile", middlewares.AuthMiddleware(), controllers.UpdateUserProfile(db))

	// Google OAuth routes
	auth.Get("/google/login", controllers.GoogleLogin(db))
	auth.Get("/google/callback", controllers.GoogleCallback(db))
}
