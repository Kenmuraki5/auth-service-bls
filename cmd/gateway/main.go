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
	clientID     = "your-client-id"
	clientSecret = "your-client-secret"
	redirectURI  = "http://localhost:8080/callback" // Your redirect URI registered in Azure AD
	scopes       = []string{"openid", "profile", "email", "offline_access", "User.Read"}
	oauthConfig  = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     microsoft.AzureADEndpoint("your-tenant-id"), // Replace with your Azure AD tenant ID
		Scopes:       scopes,
	}
)

func run() error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithInsecure()}

	err := pb.RegisterAuthServiceHandlerFromEndpoint(ctx, mux, "localhost:50053", opts)
	if err != nil {
		return err
	}

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowCredentials: true,
	})

	sm := http.NewServeMux()
	sm.HandleFunc("/", handleLogin)
	sm.HandleFunc("/callback", handleCallback)
	// sm.HandleFunc("/secure", handleSecure)
	handler := c.Handler(mux)
	log.Println("Starting HTTP/JSON gateway on port 8082")
	return http.ListenAndServe(":8082", handler)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	authURL := oauthConfig.AuthCodeURL("state")
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

// func handleSecure(w http.ResponseWriter, r *http.Request) {
// 	w.WriteHeader(http.StatusOK)
// 	w.Write([]byte("Access granted!"))
// }

func main() {
	if err := run(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
