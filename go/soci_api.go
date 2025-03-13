package main

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func main() {
	fmt.Println("Starting soci_api...")
	ctx := context.Background()
	// dbUri := "localhost:7474"
	dbUri := "neo4j://localhost"
	//dbUser := "neo4j"
	// dbPassword := "neo4j"
	// dbPassword := "decacle1234"
	driver, err := neo4j.NewDriverWithContext(
		dbUri,
		neo4j.NoAuth())
	if err != nil {
		panic(err)
	}

	err = driver.VerifyConnectivity(ctx)
	if err != nil {
		panic(err)
	}
	defer driver.Close(ctx)
	fmt.Println("connection established.")
}
