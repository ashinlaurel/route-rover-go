package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Client *mongo.Client

func ConnectDB() {
	uri := os.Getenv("MONGO_URI") // Read from .env file
	if uri == "" {
		uri = "mongodb://localhost:27017" // Default to local MongoDB
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatal("MongoDB Connection Error:", err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("MongoDB Ping Failed:", err)
	}

	fmt.Println("✅ Connected to MongoDB")
	Client = client
}

// GetCollection returns a reference to a MongoDB collection
func GetCollection(collectionName string) *mongo.Collection {
	return Client.Database("socialmedia").Collection(collectionName)
}
