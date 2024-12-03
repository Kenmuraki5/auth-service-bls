package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

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
	callbackURI         string
	redirectURI         string
	authServiceEndpoint string
	tenantID            string
	scopes              []string
	oauthConfig         oauth2.Config
)

func init() {
	clientID = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
	callbackURI = os.Getenv("CALLBACK_URI")
	redirectURI = os.Getenv("REDIRECT_URI")
	authServiceEndpoint = os.Getenv("AUTH_SERVICE_ENDPOINT")
	scopes = []string{os.Getenv("SCOPE"), "offline_access"}
	tenantID = os.Getenv("TENANT_ID")

	oauthConfig = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  callbackURI,
		Endpoint:     microsoft.AzureADEndpoint(tenantID),
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
	sm.HandleFunc("/refresh-token", handleRefreshToken)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
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

	if token.RefreshToken == "" {
		http.Error(w, "Refresh token is missing", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token.AccessToken,
		Path:     "/",
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    token.RefreshToken,
		Path:     "/",
		HttpOnly: true,
	})

	http.Redirect(w, r, redirectURI, http.StatusSeeOther)
}

func handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if requestBody.RefreshToken == "" {
		http.Error(w, "Refresh token is required", http.StatusBadRequest)
		return
	}

	refreshedToken, err := refreshToken(requestBody.RefreshToken)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	authTokenCookie := &http.Cookie{
		Name:     "auth_token",
		Value:    refreshedToken.AccessToken,
		Path:     "/",
		Domain:   "localhost",
		Expires:  time.Now().Add(120 * time.Minute),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}

	refreshTokenCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshedToken.RefreshToken,
		Path:     "/",
		Domain:   "localhost",
		Expires:  time.Now().Add(7 * 24 * time.Hour),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, authTokenCookie)
	http.SetCookie(w, refreshTokenCookie)

	response := map[string]string{
		"access_token":  refreshedToken.AccessToken,
		"refresh_token": refreshedToken.RefreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func refreshToken(refreshToken string) (*oauth2.Token, error) {
	tokenSource := oauthConfig.TokenSource(context.Background(), &oauth2.Token{
		RefreshToken: refreshToken,
	})

	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, err
	}

	return newToken, nil
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	logoutURL := fmt.Sprintf("https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri=%s", callbackURI)
	http.Redirect(w, r, logoutURL, http.StatusSeeOther)
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
