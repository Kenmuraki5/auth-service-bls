package db

import (
	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
)

func NewDB() (*gorm.DB, error) {
	db, err := gorm.Open("mysql", "root:my-secret-bls@tcp(localhost:3306)/employee-auth?charset=utf8&parseTime=True&loc=Local")
	if err != nil {
		return nil, err
	}
	return db, nil
}
