package auth

import (
	"context"
	"fmt"

	"golang.org/x/crypto/bcrypt"
	"sociapi.com/main/database"
)

var dbName = "neo4j"

type AuthService struct {
	db database.Database
}

func NewAuthService(db database.Database) *AuthService {
	return &AuthService{db: db}
}

func (authService *AuthService) Login(ctx context.Context, username string, password string) {

	user, err := authService.db.GetUser(ctx, username)
	if err != nil {
		panic(err)
	}
	fmt.Println(user.Username)

	fmt.Println(user.PasswordHash)

	//check hash against password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		panic("Invalid credentials")
	}

	fmt.Println("Successfull login")
}
