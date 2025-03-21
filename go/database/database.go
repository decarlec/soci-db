package database

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"golang.org/x/crypto/bcrypt"
)

// Encapsulates teh Neo4j driver and provides CRUD functionality
type Database struct {
	driver neo4j.DriverWithContext
}

type User struct {
	Id           string
	Username     string
	Email        string
	PasswordHash string
}

func NewDatabase(driver neo4j.DriverWithContext) *Database {
	return &Database{driver: driver}
}

func (db *Database) CreateUser(ctx context.Context, username string, password string, email string) error {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	//TODO: ensure unique usernames/emails?

	//Hash the users password.
	hashed_pwd, err := hash_pwd(password)
	if err != nil {
		panic(err)
	}

	result, err := session.Run(ctx,
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
		})

	if err != nil {
		panic(err)
	}

	if result.Next(ctx) {
		fmt.Printf("Created user: %v", result.Record())
	}
	return result.Err()
}

func (db *Database) DeleteUser(ctx context.Context, username string) error {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	result, err := session.Run(ctx,
		`MATCH (u:User {
			username: $username
		})
		DELETE u`,
		map[string]any{
			"username": username,
		})

	if err != nil {
		panic(err)
	}

	fmt.Printf("deleted user %v", username)

	return result.Err()
}

func (db *Database) GetUser(ctx context.Context, username string) (User, error) {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	fmt.Println("Getting User")

	result, err := session.Run(ctx,
		`MATCH (u:User {
			username: $username
		})
		RETURN u.id AS id, u.username as username, u.password_hash as password_hash, u.email as email`,
		map[string]any{
			"username": username,
		})

	if err != nil {
		panic(err)
	}

	if result.Next(ctx) {
		record := result.Record()

		id, ok := record.Get("id")
		if !ok {
			panic("could not decode id from database")
		}

		username, ok := record.Get("username")
		if !ok {
			panic("could not decode username from database")
		}

		email, ok := record.Get("email")
		if !ok {
			panic("could not decode email from database")
		}

		passwordHash, ok := record.Get("password_hash")
		if !ok {
			panic("could not decode password hash from the database")
		}

		return User{
			Id:           id.(string),
			Username:     username.(string),
			Email:        email.(string),
			PasswordHash: passwordHash.(string),
		}, nil
	}
	return User{}, result.Err()
}

func hash_pwd(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}
