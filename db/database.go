package db

import (
	"errors"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
)

func NewDB() (*gorm.DB, error) {
	dbHostIP := os.Getenv("DB_HOST_IP")
	dbPassword := os.Getenv("DB_PASSWORD")
	if dbHostIP == "" {
		return nil, errors.New("DB_HOST_IP environment variable is not set")
	}
	if dbPassword == "" {
		return nil, errors.New("DB_Password environment variable is not set")
	}

	db, err := gorm.Open("mysql", "root:"+dbPassword+"@tcp("+dbHostIP+":3306)/employee-auth?charset=utf8&parseTime=True&loc=Local")
	if err != nil {
		return nil, err
	}
	return db, nil
}
