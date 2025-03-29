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
		log.Panicf("Could not create password hash: %v", err)
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
	RefreshTokenVersion  int // Used to invalidate access
}

func NewDatabase(driver neo4j.DriverWithContext) *Database {
	return &Database{driver: driver}
}

func (db *Database) CreateUser(ctx context.Context, user User) (*User, error) {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	if user.Id == "" {
		user.Id = uuid.NewString()
	}

	result, err := session.Run(ctx,
		`CREATE (u:User {
			id: $id,
			username: $username,
			email: $email,
			password_hash: $password_hash,
			external_auth_provider: $external_auth_provider,
			external_auth_id: $external_auth_id
			refresh_token_version: $refresh_token_version
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
			"refresh_token_version":  user.RefreshTokenVersion,  //Auth provider user id
		})

	if err != nil {
		log.Printf("Failed to create user: %v", err)
		return nil, err
	}

	if result.Next(ctx) {
		log.Printf("Created user: %v", result.Record())
		return &user, nil
	}
	log.Printf("No user was created")
	return nil, errors.New("no user was created")
}

func (db *Database) UpdateTokens(ctx context.Context, username string, refreshToken *string, accessToken *string) (*User, error) {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	result, err := session.Run(ctx,
		`MATCH (u:User {
			username: $username
		})
		SET u.refresh_token=$refresh_token, u.access_token=$access_token`,
		map[string]any{
			"refresh_token": refreshToken,
			"access_token":  accessToken,
		})

	if err != nil {
		log.Printf("Failed to create user: %v", err)
		return nil, err
	}

	if result.Next(ctx) {
		log.Printf("Created user: %v", result.Record())
		return nil, nil
	}
	log.Printf("No user was created")
	return nil, errors.New("no user was created")
}

func (db *Database) UpdateAccessToken(ctx context.Context, username string, accessToken *string) (*User, error) {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	result, err := session.Run(ctx,
		`MATCH (u:User {
			username: $username
		})
		SET u.access_token=$access_token`,
		map[string]any{
			"access_token": accessToken,
		})

	if err != nil {
		log.Printf("Failed to create user: %v", err)
		return nil, err
	}

	if result.Next(ctx) {
		log.Printf("Created user: %v", result.Record())
		return nil, nil
	}
	log.Printf("No user was created")
	return nil, errors.New("no user was created")
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
		log.Printf("Failed to delete user: %v", err)
		return err
	}

	log.Printf("Deleted user: %v", username)
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
		log.Printf("Failed to query gothic user: %v", err)
		return nil, err
	}

	record, err := result.Single(ctx)
	if err != nil {
		log.Printf("Failed to get gothic user: %v", err)
		return nil, err
	}

	return decodeUserResult(record)
}

func (db *Database) GetUserWithName(ctx context.Context, username string) (*User, error) {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	result, err := session.Run(ctx,
		`MATCH (user:User {
			username: $username
		})
		RETURN user`,
		map[string]any{
			"username": username,
		})

	if err != nil {
		log.Printf("Failed to query user: %v", err)
		return nil, err
	}

	record, err := result.Single(ctx)
	if err != nil {
		log.Printf("Failed to get user: %v", err)
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
	user := &User{}

	// Required fields
	if id, ok := userAttributes["id"].(string); ok {
		user.Id = id
	} else {
		return nil, errors.New("missing required field: id")
	}

	// Optional fields
	if username, ok := userAttributes["username"].(string); ok {
		user.Username = username
	}
	if email, ok := userAttributes["email"].(string); ok {
		user.Email = email
	}
	if passwordHash, ok := userAttributes["password_hash"].(string); ok {
		user.PasswordHash = PasswordHash(passwordHash)
	}
	if externalAuthProvider, ok := userAttributes["external_auth_provider"].(string); ok {
		user.ExternalAuthProvider = externalAuthProvider
	}
	if externalAuthID, ok := userAttributes["external_auth_id"].(string); ok {
		user.ExternalAuthID = externalAuthID
	}

	return user, nil
}
