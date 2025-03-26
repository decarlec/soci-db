package auth

import (
	"context"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"sociapi.com/main/database"
)

type AuthService struct {
	db               database.Database
	refreshTokenLife int
	accessTokenLife  int
}

func NewAuthService(db database.Database) *AuthService {
	refreshTokenLife, err := strconv.Atoi(os.Getenv("REFRESH_TOKEN_LIFE"))
	if err != nil {
		refreshTokenLife = int(time.Hour * 24 * 30)
	}
	accessTokenLife, err := strconv.Atoi(os.Getenv("ACCESS_TOKEN_LIFE"))
	if err != nil {
		accessTokenLife = int(time.Hour / 4)
	}

	return &AuthService{
		db,
		refreshTokenLife,
		accessTokenLife,
	}
}

func (authService *AuthService) AuthenticateUser(ctx context.Context, username string, password string) (*database.User, error) {
	user, err := authService.db.GetUserWithName(ctx, username)
	if err != nil {
		return nil, err
	}

	//check hash against password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, err
	}

	log.Println("Successful login")
	return user, nil
}

func (authService *AuthService) GenerateRefreshToken(user *database.User) ([]byte, error) {
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":                 user.Id,
		"iss":                 "soci-api",
		"aud":                 getRole(user.Username),
		"exp":                 time.Now().Add(time.Duration(authService.refreshTokenLife)).Unix(),
		"iat":                 time.Now().Unix(),
		"refreshTokenVersion": user.RefreshTokenVersion,
	})

	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("REFRESH_TOKEN_SECRET")))
	if err != nil {
		return nil, err
	}

	return []byte(refreshTokenString), nil
}

func (authService *AuthService) GenerateAccessToken(user *database.User) ([]byte, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.Id,
		"iss": "soci-api",
		"aud": getRole(user.Username),
		"exp": time.Now().Add(time.Duration(authService.accessTokenLife)).Unix(),
		"iat": time.Now().Unix(),
	})

	accessTokenString, err := accessToken.SignedString([]byte(os.Getenv("ACCESS_TOKEN_SECRET")))
	if err != nil {
		return nil, err
	}

	return []byte(accessTokenString), nil
}

func getRole(username string) string {
	if username == "cdawg" {
		return "admin"
	}
	return "user"
}
