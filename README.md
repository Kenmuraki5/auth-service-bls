# auth-service-bls
docker build -t go-grpc-auth .
docker run -d --name bls-ad-auth -p 50053:50053 -p 8082:8082 --env-file .env go-grpc-auth

docker run -d --name bls-staffinfoservice -p 50051:50051 -p 8080:8080 --env-file .env go-grpc-staffinforservice