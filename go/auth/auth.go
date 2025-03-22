package auth

import (
	"context"
	"fmt"

	"golang.org/x/crypto/bcrypt"
	"sociapi.com/main/database"
)

var dbName = "neo4j"

const (
	key    = "superSecretAuthKey"
	MaxAge = 86400 * 30 // 30 days
	IsProd = false
)

type AuthService struct {
	db database.Database
}

func NewAuthService(db database.Database) *AuthService {

	return &AuthService{db: db}
}

func (authService *AuthService) Login(ctx context.Context, username string, password string) error {

	user, err := authService.db.GetUserWithName(ctx, username)
	if err != nil {
		return err
	}
	fmt.Println(user.Username)

	fmt.Println(user.PasswordHash)

	//check hash against password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return err
	}

	fmt.Println("Successfull login")
	return nil
}
