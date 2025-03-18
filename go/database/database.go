package database

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func Get_db_connection(ctx context.Context) neo4j.DriverWithContext {
	//Connect
	fmt.Println("Starting soci_api...")
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
	defer driver.Close(ctx)
	fmt.Println("Database connection established.")

	return driver
}
