package main

import (
	"context"
	"log"
	"net"

	pb "auth-service/protogen/golang/auth/authpb"

	"auth-service/db"
	"auth-service/models"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedAuthServiceServer
	db *gorm.DB
}

var jwtKey = []byte("my_secret_key")

type Claims struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	jwt.StandardClaims
}

func (s *server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return &pb.RegisterResponse{Success: false, Message: "Error hashing password"}, nil
	}

	// Assign role based on the request
	role := "user" // Default role
	if req.Role != "" {
		role = req.Role
	}

	user := models.User{
		Email:    req.Email,
		Password: string(hashedPassword),
		Role:     role,
	}

	if err := s.db.Create(&user).Error; err != nil {
		return &pb.RegisterResponse{Success: false, Message: "User already exists"}, nil
	}

	return &pb.RegisterResponse{Success: true, Message: "User registered successfully"}, nil
}

func (s *server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	var user models.User
	if err := s.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		return &pb.LoginResponse{Success: false, Message: "User not found"}, nil
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return &pb.LoginResponse{Success: false, Message: "Incorrect password"}, nil
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		Email: user.Email,
		Role:  user.Role,
	})

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return &pb.LoginResponse{Success: false, Message: "Error generating token"}, nil
	}

	return &pb.LoginResponse{Success: true, Token: tokenString, Message: "Login successful"}, nil
}

func (s *server) Authenticate(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	token, err := jwt.ParseWithClaims(req.Token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		return &pb.AuthResponse{Success: false, Message: "Invalid token"}, nil
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return &pb.AuthResponse{Success: true, Message: "Authenticated as " + claims.Email + " with role " + claims.Role}, nil
	} else {
		return &pb.AuthResponse{Success: false, Message: "Invalid token"}, nil
	}
}

func (s *server) ChangeRole(ctx context.Context, req *pb.ChangeRoleRequest) (*pb.ChangeRoleResponse, error) {
	var user models.User
	if err := s.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		return &pb.ChangeRoleResponse{Success: false, Message: "User not found"}, nil
	}

	user.Role = req.NewRole
	if err := s.db.Save(&user).Error; err != nil {
		return &pb.ChangeRoleResponse{Success: false, Message: "Failed to update role"}, nil
	}

	return &pb.ChangeRoleResponse{Success: true, Message: "Role updated successfully"}, nil
}

func main() {
	// Connect to the database
	db, err := db.NewDB()
	if err != nil {
		panic("failed to connect to database")
	}
	defer db.Close()

	// Migrate the schema
	db.AutoMigrate(&models.User{})

	// Listen for incoming gRPC requests
	lis, err := net.Listen("tcp", ":50053")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterAuthServiceServer(s, &server{db: db})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
