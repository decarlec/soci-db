package database

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/markbates/goth"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"golang.org/x/crypto/bcrypt"
)

// Encapsulates teh Neo4j driver and provides CRUD functionality
type Database struct {
	driver neo4j.DriverWithContext
}

type PasswordHash string

func NewPasswordHash(password string) PasswordHash {
	hashString, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return PasswordHash(hashString)
}

type User struct {
	Id           string
	Username     string
	Email        string
	PasswordHash PasswordHash
	//CreatedAt            neo4j.Time
	ExternalAuthProvider string
	ExternalAuthID       string
	AccessToken          string
	RefreshToken         string
}

func NewDatabase(driver neo4j.DriverWithContext) *Database {
	return &Database{driver: driver}
}

func (db *Database) CreateUser(ctx context.Context, user User) error {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	//TODO: ensure unique usernames/emails?

	//Hash the users password.
	result, err := session.Run(ctx,
		`CREATE (u:User {
			id: $id,
			username: $username,
			email: $email,
			password_hash: $password_hash,
			external_auth_provider: $external_auth_provider,
			external_auth_id: $external_auth_id
		}) 
		RETURN u`,

		map[string]any{
			"id":            uuid.New().String(),
			"username":      user.Username,
			"email":         user.Email,
			"password_hash": string(user.PasswordHash),
			//			"created_at": time.Now(),
			"external_auth_provider": user.ExternalAuthProvider, //Auth provider eg. google
			"external_auth_id":       user.ExternalAuthID,       //Auth provider user id
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

func (db *Database) GetGothicUser(ctx context.Context, user goth.User) (*User, error) {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	result, err := session.Run(ctx,
		`MATCH (u:User {
			external_auth_provider: $external_auth_provider
			external_auth_id: $external_auth_id
		})
		RETURN u`,
		map[string]any{
			"external_auth_provider": user.Provider,
			"external_auth_id":       user.UserID,
		})

	if err != nil {
		panic(err)
	}

	if result.Next(ctx) {
		record := result.Record()

		return decodeUserResult(record)
	}
	return nil, result.Err()

}

func (db *Database) GetUserWithName(ctx context.Context, username string) (*User, error) {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	log.Println("Get User With Name")

	result, err := session.Run(ctx,
		`MATCH (u:User {
			username: $username
		})
		RETURN u`,
		map[string]any{
			"username": username,
		})

	if err != nil {
		panic(err)
	}

	if result.Next(ctx) {
		record := result.Record()

		return decodeUserResult(record)
	}
	return nil, result.Err()
}

func decodeUserResult(record *neo4j.Record) (*User, error) {
	id, ok := record.Get("id")
	if !ok {
		return nil, errors.New("could not decode id from database")
	}

	username, ok := record.Get("username")
	if !ok {
		return nil, errors.New("could not decode username from database")
	}

	email, ok := record.Get("email")
	if !ok {
		return nil, errors.New("could not decode email from database")
	}

	passwordHash, ok := record.Get("password_hash")
	if !ok {
		return nil, errors.New("could not decode password hash from the database")
	}

	external_auth_provider, ok := record.Get("external_auth_provider")
	if !ok {
		return nil, errors.New("could not decode auth provider the database")
	}

	external_auth_id, ok := record.Get("external_auth_id")
	if !ok {
		return nil, errors.New("could not decode auth id from the database")
	}

	return &User{
		Id:                   id.(string),
		Username:             username.(string),
		Email:                email.(string),
		PasswordHash:         PasswordHash(passwordHash.(string)),
		ExternalAuthProvider: external_auth_provider.(string),
		ExternalAuthID:       external_auth_id.(string),
	}, nil
}
