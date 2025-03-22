package main

import (
	"context"
	"fmt"
	"html/template"
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
	"sociapi.com/main/test"
)

func main() {
	//Setup logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)

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

	goth.UseProviders(google.New(googleClientId, googleClientSecret, "http://localhost:3000/auth/callback?provider=google"))

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

	r.Get("/", func(writer http.ResponseWriter, request *http.Request) {
		t, _ := template.New("foo").Parse(indexTemplate)
		t.Execute(writer, nil)
	})

	r.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		gothic.BeginAuthHandler(w, r)
	})

	r.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		gothUser, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}

		//appUser, err := findOrCreateUser(gothUser)

		log.Printf("creating user: %v", gothUser)

		refresh, access, err := create_tokens(gothUser, w)
		if err != nil {
			panic(err)
		}
		t, _ := template.New("foo").Parse(userTemplate)
		w.Write([]byte(refresh))
		w.Write([]byte(access))
		t.Execute(w, gothUser)
	})

	test.Create_user_and_login(db, auth)

	http.ListenAndServe(":3000", r)
}

// func findOrCreateUser(db database.Database, gothUser goth.User) (*database.User, error) {
// 	appUser := db.GetUser(context.Background())
// }

// func findOrCreateUser(db database.Database, user database.User) (*database.User, error) {
// 	appUser := db.CreateUser(context.Background(), user)
// }

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

// Note that the URLs to authenticate with the various providers are different as
// well.
var indexTemplate = `
<p><a href="/auth?provider=twitter">Log in with Twitter</a></p>
<p><a href="/auth?provider=facebook">Log in with Facebook</a></p>
<p><a href="/auth?provider=google">Log in with Google</a></p>
`

var userTemplate = `
<p>Name: {{.Name}}</p>
<p>Email: {{.Email}}</p>
<p>NickName: {{.NickName}}</p>
<p>Location: {{.Location}}</p>
<p>AvatarURL: {{.AvatarURL}} <img src="{{.AvatarURL}}"></p>
<p>Description: {{.Description}}</p>
<p>UserID: {{.UserID}}</p>
<p>AccessToken: {{.AccessToken}}</p>`
