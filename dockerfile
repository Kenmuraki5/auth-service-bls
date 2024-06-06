# Build stage
FROM golang:1.22-alpine AS builder

# Set environment variables
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# Set the Current Working Directory inside the container
WORKDIR /build

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download


# Copy the source directories
COPY . ./

# Build the Go apps
RUN go build -o /go-server cmd/server/main.go
RUN go build -o /go-gateway cmd/gateway/main.go

# Run stage
FROM alpine:latest

WORKDIR /root/

# Copy the Pre-built binary files from the previous stage
COPY --from=builder /go-server .
COPY --from=builder /go-gateway .

# Expose port 50051 for gRPC and 8080 for HTTP
EXPOSE 50051 8080

# Command to run both binaries
CMD ["sh", "-c", "./go-server & ./go-gateway"]
