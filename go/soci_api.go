package main

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"

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

type Server struct {
	ctx       context.Context
	db        *database.Database
	auth      *auth.AuthService
	router    *chi.Mux
	templates *template.Template
}

func NewServer(ctx context.Context, db *database.Database, auth *auth.AuthService) *Server {
	templates := template.Must(template.ParseFiles(
		filepath.Join("templates", "login.html"),
		filepath.Join("templates", "user.html"),
	))

	s := &Server{
		ctx:       ctx,
		db:        db,
		auth:      auth,
		router:    chi.NewRouter(),
		templates: templates,
	}
	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	s.router.Use(middleware.Logger)

	// Static files
	fs := http.FileServer(http.Dir("static"))
	s.router.Handle("/static/*", http.StripPrefix("/static", fs))

	// Routes
	s.router.Get("/", s.handleHome)
	s.router.Post("/login", handleLogin(s.auth))
	s.router.HandleFunc("/auth", handleAuth)
	s.router.HandleFunc("/auth/callback", handleAuthCallback(s.db, s.auth))
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if err := s.templates.ExecuteTemplate(w, "login.html", nil); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func handleLogin(auth *auth.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		err := auth.Login(r.Context(), r.FormValue("username"), r.FormValue("password"))
		if err != nil {
			http.Error(w, "Auth failed 😿", http.StatusUnauthorized)
			return
		}
		w.Write([]byte("success! 😸"))
	}
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	gothic.BeginAuthHandler(w, r)
}

func handleAuthCallback(db *database.Database, auth *auth.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gothUser, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		log.Printf("creating user: %v", gothUser)
		appUser, err := findOrCreateUser(r.Context(), db, gothUser)
		if err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		refresh, access, err := auth.GenerateTokens(gothUser, w)
		if err != nil {
			http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
			return
		}

		templates := template.Must(template.ParseFiles(filepath.Join("templates", "user.html")))
		if err := templates.ExecuteTemplate(w, "user.html", gothUser); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		userJson, err := json.Marshal(appUser)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(userJson)
		w.Write(refresh)
		w.Write(access)
	}
}

func (s *Server) Start(addr string) error {
	return http.ListenAndServe(addr, s.router)
}

func main() {
	ctx := context.Background()
	//Setup logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	//Load up env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
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

	// Create and start server
	server := NewServer(ctx, db, auth)
	if err := server.Start("localhost:3000"); err != nil {
		log.Fatal(err)
	}
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
