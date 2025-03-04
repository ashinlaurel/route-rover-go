package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name           string             `bson:"name" json:"name"`
	Email          string             `bson:"email" json:"email"`
	Password       string             `bson:"password,omitempty" json:"-"`
	GoogleID       string             `bson:"google_id,omitempty" json:"-"`
	AuthProvider   string             `bson:"auth_provider,omitempty" json:"auth_provider"`
	ProfilePicture string             `bson:"profile_picture,omitempty" json:"profile_picture"`
}

func (User) CollectionName() string {
	return "users"
}
