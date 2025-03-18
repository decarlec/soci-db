package auth

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"golang.org/x/crypto/bcrypt"
	"sociapi.com/main/database"
)

var dbName = "neo4j"

func Login(username string, password string) {
	var ctx = context.Background()
	var driver = database.Init_driver(ctx)
	defer driver.Close(ctx)

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
