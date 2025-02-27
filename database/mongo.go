package database

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// DatabaseHandler struct to manage database connections
type DatabaseHandler struct {
	Client         *mongo.Client
	Database       *mongo.Database
	UserCollection *mongo.Collection
}

// NewDatabase initializes the MongoDB connection
func NewDatabase() (*DatabaseHandler, error) {
	uri := "mongodb://localhost:27017"
	clientOptions := options.Client().ApplyURI(uri)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, err
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	fmt.Println("Connected to MongoDB!")

	// Initialize collections
	db := client.Database("route-rover-dev")

	return &DatabaseHandler{
		Client:         client,
		Database:       db,
		UserCollection: db.Collection("users"),
	}, nil
}
