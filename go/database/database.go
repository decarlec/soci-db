package database

import (
	"context"
	"errors"
	"log"

	"github.com/google/uuid"
	"github.com/markbates/goth"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"
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

func (db *Database) CreateUser(ctx context.Context, user User) (*User, error) {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	//Get user in shape!
	if user.Id == "" {
		user.Id = uuid.NewString()
	}

	//TODO: check if username exists to ensure unique usernames/emails?

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
			"id":            user.Id,
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
		log.Printf("Created user: %v", result.Record())
		return &user, nil
	}
	return nil, result.Err()
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

	log.Printf("deleted user: %v", username)

	return result.Err()
}

func (db *Database) GetGothicUser(ctx context.Context, user goth.User) (*User, error) {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	result, err := session.Run(ctx,
		`MATCH (user:User {
			external_auth_provider: $external_auth_provider,
			external_auth_id: $external_auth_id
		})
		RETURN user`,
		map[string]any{
			"external_auth_provider": user.Provider,
			"external_auth_id":       user.UserID,
		})

	if err != nil {
		panic(err)
	}

	record, err := result.Single(ctx)
	if err != nil {
		return nil, err
	}

	return decodeUserResult(record)
}

func (db *Database) GetUserWithName(ctx context.Context, username string) (*User, error) {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	log.Println("Get User With Name")

	result, err := session.Run(ctx,
		`MATCH (user:User {
			username: $username
		})
		RETURN user`,
		map[string]any{
			"username": username,
		})

	if err != nil {
		panic(err)
	}

	record, err := result.Single(ctx)
	if err != nil {
		return nil, err
	}

	return decodeUserResult(record)
}

func decodeUserResult(record *neo4j.Record) (*User, error) {
	userRecord, ok := record.Get("user")
	if !ok {
		return nil, errors.New("could not get user record")
	}

	userAttributes := userRecord.(dbtype.Node).Props

	return &User{
		Id:                   userAttributes["id"].(string),
		Username:             userAttributes["username"].(string),
		Email:                userAttributes["email"].(string),
		PasswordHash:         PasswordHash(userAttributes["password_hash"].(string)),
		ExternalAuthProvider: userAttributes["external_auth_provider"].(string),
		ExternalAuthID:       userAttributes["external_auth_id"].(string),
	}, nil
}
