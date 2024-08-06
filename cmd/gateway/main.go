package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	pb "github.com/Kenmuraki5/auth-service-bls/protogen/golang/auth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/cors"
	"google.golang.org/grpc"
)

var (
	clientID            string
	clientSecret        string
	redirectURI         string
	authServiceEndpoint string
	scopes              = []string{"api://11cc4082-999e-4685-8d91-4b0841455042/Custom.Read"}
	oauthConfig         oauth2.Config
)

func init() {
	clientID = "11cc4082-999e-4685-8d91-4b0841455042"
	clientSecret = "2md8Q~TuHUwBQgS1dnkEDzbwK~QgAWrtndnFvafp"
	redirectURI = "http://localhost:8082/callback"
	authServiceEndpoint = "localhost:50053"

	oauthConfig = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     microsoft.AzureADEndpoint("06ea85c4-63ba-43bf-8e3b-4705681e959c"),
		Scopes:       scopes,
	}
}

func run() error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	gwmux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithInsecure()}

	err := pb.RegisterAuthServiceHandlerFromEndpoint(ctx, gwmux, authServiceEndpoint, opts)
	if err != nil {
		return err
	}

	sm := http.NewServeMux()
	sm.Handle("/authpb.AuthService/", gwmux)
	sm.HandleFunc("/login", handleLogin)
	sm.HandleFunc("/callback", handleCallback)
	sm.HandleFunc("/logout", handleLogout)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowCredentials: true,
	})

	handler := c.Handler(sm)
	log.Println("Starting HTTP/JSON gateway on port 8082")
	return http.ListenAndServe(":8082", handler)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	authURL := oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	code := r.URL.Query().Get("code")

	token, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, fmt.Sprintf("OAuth exchange failed: %v", err), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token.AccessToken,
		Path:     "/",
		HttpOnly: true,
	})

	http.Redirect(w, r, "http://localhost:3000", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1, // Expire immediately
	})

	logoutURL := fmt.Sprintf("https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri=%s", redirectURI)
	http.Redirect(w, r, logoutURL, http.StatusSeeOther)
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
