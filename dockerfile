FROM golang:1.22-alpine AS builder

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64


WORKDIR /build


COPY go.mod go.sum ./


RUN go mod download


COPY . ./


RUN go build -o /go-server cmd/server/main.go
RUN go build -o /go-gateway cmd/gateway/main.go


FROM alpine:latest

WORKDIR /root/

COPY --from=builder /go-server .
COPY --from=builder /go-gateway .

EXPOSE 50051 8080

CMD ["sh", "-c", "./go-server & ./go-gateway"]
