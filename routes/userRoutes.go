package routes

import (
	"route-rover-go/controllers"
	"route-rover-go/database"

	"github.com/gofiber/fiber/v2"
)

func UserRoutes(app *fiber.App, db *database.DatabaseHandler) {
	api := app.Group("/api")
	api.Post("/register", controllers.RegisterUser(db))
	api.Post("/login", controllers.LoginUser(db))
	// api.Get("/users", controllers.GetUsers)
}
