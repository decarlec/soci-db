package main

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lpernett/godotenv"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"

	"sociapi.com/main/auth"
	"sociapi.com/main/database"
	"sociapi.com/main/setup"
)

var ctx context.Context

func main() {
	ctx = context.Background()
	//Setup logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	//Load up env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loding .env file")
	}

	//Open database driver
	driver := setup.Get_db_driver(ctx)
	defer driver.Close(ctx)

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

	//root
	r.Get("/", func(writer http.ResponseWriter, request *http.Request) {
		t, _ := template.New("foo").Parse(indexTemplate)
		t.Execute(writer, nil)
	})

	//setup static file serving
	fs := http.FileServer(http.Dir("static"))
	r.Handle("/static/*", http.StripPrefix("/static", fs))

	//Basic auth login
	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/", http.StatusFound)
		}
		err := auth.Login(r.Context(), r.FormValue("username"), r.FormValue("password"))
		if err != nil {
			http.Error(w, "Auth failed 😿", http.StatusUnauthorized)
		} else {
			w.Write([]byte("success! 😸"))
		}
	})

	// Goth (external auth providers)
	r.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		gothic.BeginAuthHandler(w, r)
	})

	r.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		gothUser, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}

		log.Printf("creating user: %v", gothUser)
		appUser, err := findOrCreateUser(r.Context(), db, gothUser)
		if err != nil {
			panic(err)
		}

		refresh, access, err := auth.GenerateTokens(gothUser, w)
		if err != nil {
			panic(err)
		}
		log.Println(refresh)
		log.Println(access)
		t, _ := template.New("foo").Parse(userTemplate)
		w.Write([]byte(refresh))
		w.Write([]byte(access))

		userJson, err := json.Marshal(appUser)
		if err != nil {
			panic(err)
		}
		w.Write(userJson)
		log.Println(userJson)
		t.Execute(w, gothUser)
	})

	http.ListenAndServe("localhost:3000", r)
}

// Create a gothic user,
func findOrCreateUser(ctx context.Context, db *database.Database, gothUser goth.User) (*database.User, error) {
	appUser, err := db.GetGothicUser(ctx, gothUser)
	if err != nil {
		return nil, err
	}

	if appUser != nil {
		return appUser, nil
	}

	return db.CreateUser(ctx, database.User{
		Id:                   uuid.NewString(),
		Email:                gothUser.Email,
		ExternalAuthProvider: gothUser.Provider,
		ExternalAuthID:       gothUser.UserID,
	})
}

// Note that the URLs to authenticate with the various providers are different as
// well.
var indexTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Login Page</title>
    <link rel="stylesheet" type="text/css" href="/static/style.css">
</head>
<body>
    <div class="login-container">
        <h2>Login</h2>
        <form action="/login" method="POST">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required><br>
            <button class="login-button" type="submit">Login</button>
        </form>
		<button class="google" onclick="location.href='/auth?provider=google'">Log in with Google</a></button>
    </div>
</body>
</html>
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
