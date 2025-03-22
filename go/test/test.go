package test

import (
	"context"
	"log"

	"sociapi.com/main/auth"
	"sociapi.com/main/database"
)

func create_user_and_login(db database.Database, auth auth.AuthService) {
	// Delete user if exists
	user := "cdawg"
	err := db.DeleteUser(context.Background(), user)

	if err != nil {
		log.Printf("User '%v' did not delete. error: %v", user, err)
	}
	hashed_pwd, err := hash_pwd("dawg")
	if err != nil {
		panic(err)
	}

	// Create new user
	err = db.CreateUser(context.Background(), user, "dawg", "dawg@dawg.com")

	if err != nil {
		panic(err)
	}

	// Login as new user
	log.Println("logging in")
	auth.Login(context.Background(), user, "dawg")

}
