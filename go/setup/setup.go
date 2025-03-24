package setup

import (
	"context"
	"log"
	"os"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func Get_db_driver(ctx context.Context) neo4j.DriverWithContext {
	dbUri := os.Getenv("NEO4J_URI")
	if dbUri == "" {
		dbUri = "neo4j://localhost:7687"
	}
	dbUser := os.Getenv("NEO4J_USER")
	if dbUser == "" {
		dbUser = "neo4j"
	}
	dbPassword := os.Getenv("NEO4J_PASSWORD")
	if dbPassword == "" {
		dbPassword = "password1234"
	}

	driver, err := neo4j.NewDriverWithContext(
		dbUri,
		neo4j.BasicAuth(dbUser, dbPassword, ""))
	if err != nil {
		log.Fatalf("Failed to create Neo4j driver: %v", err)
	}

	err = driver.VerifyConnectivity(ctx)
	if err != nil {
		log.Fatalf("Failed to connect to Neo4j: %v", err)
	}
	log.Println("Database connection established.")
	return driver
}
