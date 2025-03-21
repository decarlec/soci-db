package main

import (
	"context"
	"fmt"
	"log"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"sociapi.com/main/auth"
	"sociapi.com/main/database"
)

func main() {
	//Open database driver
	driver := get_db_driver(context.Background())
	defer driver.Close(context.Background())

	db := database.NewDatabase(driver)

	// Delete user if exists
	user := "cdawg"
	err := db.DeleteUser(context.Background(), user)

	if err != nil {
		log.Printf("User '%v' did not delete. error: %v", user, err)
	}

	// Create new user
	err = db.CreateUser(context.Background(), user, "dawg", "dawg@dawg.com")

	if err != nil {
		panic(err)
	}

	// Login as new user
	authService := auth.NewAuthService(*db)

	log.Println("logging in")
	authService.Login(context.Background(), user, "dawg")
}

func get_db_driver(ctx context.Context) neo4j.DriverWithContext {
	dbUri := "neo4j://localhost:7687"
	dbUser := "neo4j"
	dbPassword := "password1234"
	driver, err := neo4j.NewDriverWithContext(
		dbUri,
		neo4j.BasicAuth(dbUser, dbPassword, ""))
	if err != nil {
		panic(err)
	}

	err = driver.VerifyConnectivity(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("Database connection established.")
	return driver
}
