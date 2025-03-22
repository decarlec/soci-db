package setup

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func Get_db_driver(ctx context.Context) neo4j.DriverWithContext {
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
