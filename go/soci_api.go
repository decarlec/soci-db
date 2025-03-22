package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lpernett/godotenv"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"sociapi.com/main/auth"
	"sociapi.com/main/database"
)

func main() {
	//Load up env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loding .env file")
	}

	//Open database driver
	driver := get_db_driver(context.Background())
	defer driver.Close(context.Background())

	// Instantiate db and auth services
	db := database.NewDatabase(driver)

	auth := auth.NewAuthService(*db)

	// Start goth
	googleClientId := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")

	goth.UseProviders(google.New(googleClientId, googleClientSecret, "http://localhost:3000/auth/google/callback", "read"))

	// Spin up chi
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})

	//THIS IS A TOTALLY VALID AND SECURE WAY TO LOGIN
	r.Get("/login/{user}/{password}", func(w http.ResponseWriter, r *http.Request) {
		err := auth.Login(context.Background(), r.PathValue("user"), r.PathValue("password"))
		if err != nil {
			http.Error(w, "Auth failed 😿", http.StatusUnauthorized)
		} else {
			w.Write([]byte("success! 😸"))
		}
	})

	r.HandleFunc("/auth/{provider}/authorize", func(w http.ResponseWriter, r *http.Request) {
		gothic.BeginAuthHandler(w, r)
	})

	r.HandleFunc("/auth/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
		gothUser, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}

		appUser, err := findOrCreateUser(gothUser)

		refresh, access, err := create_tokens(gothUser, w)

		w.Write([]byte(refresh))
	})

	http.ListenAndServe(":3000", r)
}

func findOrCreateUser(db database.Database, gothUser goth.User) (*database.User, error) {
	appUser := db.GetUser(context.Background())
}

func findOrCreateUser(db database.Database, user database.User) (*database.User, error) {
	appUser := db.CreateUser(context.Background(), user)
}

func create_tokens(user goth.User, w http.ResponseWriter) ([]byte, []byte, error) {
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
	})

	refreshTokenString, err := refreshToken.SignedString([]byte("add a real secret"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, nil, err
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
	})

	accessTokenString, err := accessToken.SignedString([]byte("add a real secret"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, nil, err
	}

	return []byte(refreshTokenString), []byte(accessTokenString), nil
}

func get_db_driver(ctx context.Context) neo4j.DriverWithContext {
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
