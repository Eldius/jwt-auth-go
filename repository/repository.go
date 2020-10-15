package repository

import (
	"github.com/Eldius/jwt-auth-go/config"
	"github.com/Eldius/jwt-auth-go/user"
	"github.com/jinzhu/gorm"

	// I need this
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

var db *gorm.DB

// GetDB gets a database connection
func GetDB() *gorm.DB {
	if db == nil {
		db = initDB()
	}
	return db
}

func initDB() *gorm.DB {
	db, err := gorm.Open(config.GetDBEngine(), config.GetDBURL())
	if err != nil {
		panic("failed to connect database")
	}
	if config.GetDBLogQueries() {
		db.LogMode(true)
	}
	db.AutoMigrate(&user.CredentialInfo{}, &user.Profile{})
	return db
}
