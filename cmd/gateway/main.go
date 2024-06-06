package main

import (
	"context"
	"log"
	"net/http"

	pb "github.com/Kenmuraki5/auth-service-bls/protogen/golang/auth"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/cors"
	"google.golang.org/grpc"
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

	handler := c.Handler(mux)
	log.Println("Starting HTTP/JSON gateway on port 8082")
	return http.ListenAndServe(":8082", handler)
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
