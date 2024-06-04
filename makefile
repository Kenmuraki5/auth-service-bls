build:
	protoc --go_out=./protogen/golang --go-grpc_out=./protogen/golang auth.proto
