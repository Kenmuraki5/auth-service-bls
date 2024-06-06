# auth-service-bls
docker build -t go-grpc-auth .
docker run -p 50053:50053 -p 8082:8082 --env-file .env go-grpc-auth

