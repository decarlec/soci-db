package auth

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/markbates/goth"
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

func (authService *AuthService) Login(ctx context.Context, username string, password string) error {

	user, err := authService.db.GetUserWithName(ctx, username)
	if err != nil {
		return err
	}
	log.Println(user.Username)

	log.Println(user.PasswordHash)

	//check hash against password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return err
	}

	log.Println("Successfull login")
	return nil
}

func (authService *AuthService) GenerateTokens(user goth.User, w http.ResponseWriter) ([]byte, []byte, error) {
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
	})

	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("REFRESH_TOKEN_SECRET")))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, nil, err
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
	})

	accessTokenString, err := accessToken.SignedString([]byte(os.Getenv("ACCESS_TOKEN_SECRET")))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, nil, err
	}

	return []byte(refreshTokenString), []byte(accessTokenString), nil
}
