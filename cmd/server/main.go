package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"

	pb "github.com/Kenmuraki5/auth-service-bls/protogen/golang/auth"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedAuthServiceServer
}

var (
	publicKeys map[string]*rsa.PublicKey
	jwkSetURL  string
)

func (s *server) Authenticate(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	authHeader := req.Token
	if authHeader == "" {
		return &pb.AuthResponse{Success: false, Message: "Authorization token is required"}, nil
	}
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		return &pb.AuthResponse{Success: false, Message: "Malformed token"}, nil
	}

	token := tokenParts[1]

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid not found in token header")
		}
		key, ok := publicKeys[kid]
		if !ok {
			return nil, fmt.Errorf("no matching key found for kid: %s", kid)
		}
		return key, nil
	})
	if err != nil {
		return &pb.AuthResponse{Success: false, Message: fmt.Sprintf("Token validation failed: %v", err)}, nil
	}
	if !parsedToken.Valid {
		return &pb.AuthResponse{Success: false, Message: "Token is not valid"}, nil
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return &pb.AuthResponse{Success: false, Message: "Token claims are not valid"}, nil
	}

	roles, err := extractRoles(claims)
	if err != nil {
		return &pb.AuthResponse{Success: false, Message: err.Error()}, nil
	}

	return &pb.AuthResponse{Success: true, Message: "Token is valid", Roles: roles}, nil
}

func extractRoles(claims jwt.MapClaims) ([]string, error) {
	roleClaim, ok := claims["roles"]
	if !ok {
		return nil, fmt.Errorf("roles claim not found")
	}

	roleSlice, ok := roleClaim.([]interface{})
	if !ok {
		return nil, fmt.Errorf("roles claim is not a slice")
	}

	roles := make([]string, len(roleSlice))
	for i, role := range roleSlice {
		roleStr, ok := role.(string)
		if !ok {
			return nil, fmt.Errorf("role is not a string")
		}
		roles[i] = roleStr
	}

	return roles, nil
}

func getPublicKeys() (map[string]*rsa.PublicKey, error) {
	resp, err := http.Get(jwkSetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %v", err)
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			E   string `json:"e"`
			N   string `json:"n"`
		} `json:"keys"`
	}

	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %v", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return nil, fmt.Errorf("failed to decode N: %v", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return nil, fmt.Errorf("failed to decode E: %v", err)
		}
		e := 0
		for _, b := range eBytes {
			e = e*256 + int(b)
		}
		key := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: e,
		}
		keys[jwk.Kid] = key
		fmt.Printf("Loaded key %s\n", jwk.Kid)
	}

	return keys, nil
}

func main() {
	tenantID := os.Getenv("TENANT_ID")
	if tenantID == "" {
		log.Fatal("TENANT_ID environment variable is not set")
	}

	jwkSetURL = fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", tenantID)

	var err error
	publicKeys, err = getPublicKeys()
	if err != nil {
		log.Fatalf("Failed to get public keys: %v", err)
	}

	lis, err := net.Listen("tcp", ":50053")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterAuthServiceServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
