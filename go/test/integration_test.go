package test

import (
	"context"
	"log"

	"sociapi.com/main/auth"
	"sociapi.com/main/database"
)

func Create_user_and_login(db *database.Database, auth *auth.AuthService) {
	// Delete user if exists
	username := "cdawg"
	password := "dawg"
	err := db.DeleteUser(context.Background(), username)

	if err != nil {
		log.Printf("User '%v' did not delete. error: %v", username, err)
	}

	// Create new user
	user, err := db.CreateUser(context.Background(), database.User{Username: username, PasswordHash: database.NewPasswordHash(password), Email: "dawg@dawg.com"})
	log.Printf("User created: %v", user)

	if err != nil {
		panic(err)
	}

	// Login as new user
	log.Println("logging in")
	auth.AuthenticateUser(context.Background(), username, password)
}
