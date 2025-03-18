package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"golang.org/x/crypto/bcrypt"
	"sociapi.com/main/auth"
	"sociapi.com/main/database"
)

var driver neo4j.DriverWithContext
var ctx context.Context

const dbName string = "neo4j"

func main() {
	user := "cdawg"
	ctx = context.Background()
	driver = database.Init_driver(ctx)
	defer driver.Close(ctx)

	err := delete_user(user)
	if err != nil {
		fmt.Printf("User '%v' did not delete. error: %v", user, err)
	}

	create_user("cdawg", "dawg@dawg.com", "dawg")

	auth.Login("dawg", "dawg")
}

func hash_pwd(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

func delete_user(username string) error {
	result, err := neo4j.ExecuteQuery(ctx, driver,
		`MATCH (u:User {
			username: $username
		})
		DELETE u`,
		map[string]any{
			"username": username,
		},
		neo4j.EagerResultTransformer,
		neo4j.ExecuteQueryWithDatabase(dbName))

	if err != nil {
		return err
	}
	summary := result.Summary
	fmt.Printf("Deleted %v user nodes in %+v.\n",
		summary.Counters().NodesDeleted(),
		summary.ResultAvailableAfter())

	return err
}

func create_user(username string, email string, password string) {
	//TODO: ensure unique usernames/emails?

	//Hash the users password.
	hashed_pwd, err := hash_pwd(password)
	if err != nil {
		panic(err)
	}

	result, err := neo4j.ExecuteQuery(ctx, driver,
		`CREATE (u:User {
			id: $id,
			username: $username,
			email: $email,
			password_hash: $password_hash
		}) 
		RETURN u`,
		map[string]any{
			"id":            uuid.New().String(),
			"username":      username,
			"email":         email,
			"password_hash": string(hashed_pwd),
		}, neo4j.EagerResultTransformer,
		neo4j.ExecuteQueryWithDatabase(dbName))

	if err != nil {
		panic(err)
	}

	summary := result.Summary
	fmt.Printf("Created %v user nodes in %+v.\n",
		summary.Counters().NodesCreated(),
		summary.ResultAvailableAfter())

}
