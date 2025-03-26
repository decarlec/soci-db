package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt"
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
	//s.router.Use(middleware.Recoverer)
	//s.router.Use(middleware.Timeout(60 * time.Second))

	//Protected Routes
	s.router.Group(func(r chi.Router) {
		r.Use(AuthMiddleWare)
		r.HandleFunc("/protected", s.handleProtected)
	})

	//TODO: Why these defaults?
	// s.router.Use(middleware.RequestID)
	// s.router.Use(middleware.RealIP)
	fs := http.FileServer(http.Dir("static"))

	s.router.Group(func(r chi.Router) {
		// Static files
		r.Handle("/static/*", http.StripPrefix("/static", fs))

		// Public Routes
		r.Get("/", s.handleHome)
		r.Post("/login", handleLogin(s.auth))
		r.HandleFunc("/auth", handleAuth)
		r.HandleFunc("/auth/callback", handleAuthCallback(s.db, s.auth))

	})

}

func AuthMiddleWare(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing auth header.", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid auth header format", http.StatusUnauthorized)
		}

		tokenString := parts[1]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("ACCESS_TOKEN_SECRET")), nil
		})

		if err != nil {
			http.Error(w, "Invalid access token.", http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			log.Printf("User logged in with claims: %v", claims)
			handler.ServeHTTP(w, r)
		}
	})
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if err := s.templates.ExecuteTemplate(w, "login.html", nil); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleProtected(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("WOW, you're official! 🙀"))
}

func handleLogin(auth *auth.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		user, err := auth.AuthenticateUser(r.Context(), r.FormValue("username"), r.FormValue("password"))
		if err != nil {
			http.Error(w, "Auth failed 😿", http.StatusUnauthorized)
			return
		}

		refresh, err := auth.GenerateRefreshToken(user)
		if err != nil {
			http.Error(w, "Auth failed 😿, couldn't generate refresh token", http.StatusUnauthorized)
			return
		}

		access, err := auth.GenerateAccessToken(user)
		if err != nil {
			http.Error(w, "Auth failed 😿, couldn't generate access token", http.StatusUnauthorized)
			return
		}

		w.Header().Add("Authorization", fmt.Sprintf("Bearer %v", access))
		w.Write(refresh)

		// rCookie := http.Cookie{
		// 	Name:     "refreshCookie",
		// 	Value:    string(refresh),
		// 	Path:     "/",
		// 	MaxAge:   3600,
		// 	HttpOnly: true,
		// 	Secure:   true,
		// 	SameSite: http.SameSiteLaxMode,
		// }

		// aCookie := http.Cookie{
		// 	Name:     "accessCookie",
		// 	Value:    string(access),
		// 	Path:     "/",
		// 	MaxAge:   3600,
		// 	HttpOnly: true,
		// 	Secure:   true,
		// 	SameSite: http.SameSiteLaxMode,
		// }

		// http.SetCookie(w, &rCookie)
		// http.SetCookie(w, &aCookie)

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

		refresh, err := auth.GenerateRefreshToken(appUser)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		access, err := auth.GenerateAccessToken(appUser)
		if err != nil {
			http.Error(w, "Failed to access token", http.StatusInternalServerError)
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
		w.Header().Add("Authorization", fmt.Sprintf("Bearer %v", access))
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
