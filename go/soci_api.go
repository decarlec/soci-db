package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"golang.org/x/crypto/bcrypt"
)

var driver neo4j.DriverWithContext
var ctx context.Context

const dbName string = "neo4j"

func main() {
	//Connect
	fmt.Println("Starting soci_api...")
	ctx = context.Background()
	dbUri := "neo4j://localhost:7687"
	dbUser := "neo4j"
	dbPassword := "password1234"
	var err error
	driver, err = neo4j.NewDriverWithContext(
		dbUri,
		neo4j.BasicAuth(dbUser, dbPassword, ""))
	if err != nil {
		panic(err)
	}

	err = driver.VerifyConnectivity(ctx)
	if err != nil {
		panic(err)
	}
	defer driver.Close(ctx)
	fmt.Println("Database connection established.")

	user := "cdawg"
	err = delete_user(user)
	if err != nil {
		fmt.Printf("User '%v' did not delete. error: %v", user, err)
	}

	create_user("cdawg", "dawg@dawg.com", "dawg")

	login("cdawg", "dawg")
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

func login(username string, password string) {
	err := driver.VerifyConnectivity(ctx)
	if err != nil {
		panic(err)
	}

	// get user
	result, err := neo4j.ExecuteQuery(ctx, driver,
		`MATCH (u:User {
			username: $username
		})
		RETURN u`,
		map[string]any{
			"username": username,
		},
		neo4j.EagerResultTransformer,
		neo4j.ExecuteQueryWithDatabase(dbName))
	if err != nil {
		panic(err)
	}

	if len(result.Records) != 1 {
		panic("duplicate user detected")
	}

	// extract user node
	userNode, _ := result.Records[0].Get("u")
	user, ok := userNode.(neo4j.Node)
	if !ok {
		panic("expected a node")
	}

	// get hash
	passwordHash := user.Props["password_hash"].(string)

	//check hash against password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		panic("Invalid credentials")
	}

	fmt.Printf("The 'login query' `%v` returned %v records in %+v.\n",
		result.Summary.Query().Text(), len(result.Records),
		result.Summary.ResultAvailableAfter())
}
