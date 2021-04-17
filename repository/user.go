package repository

import (
	"log"

	"github.com/Eldius/jwt-auth-go/config"
	"github.com/Eldius/jwt-auth-go/user"
	"github.com/jinzhu/gorm"
)

type AuthRepository struct {
	db *gorm.DB
}

func NewRepository() *AuthRepository {
	db, err := gorm.Open(config.GetDBEngine(), config.GetDBURL())
	if err != nil {
		panic("failed to connect database")
	}
	if config.GetDBLogQueries() {
		db.LogMode(true)
	}
	db.AutoMigrate(&user.CredentialInfo{}, &user.Profile{})

	return &AuthRepository{
		db: db,
	}
}

func NewRepositoryCustom(db *gorm.DB) *AuthRepository {
	db.AutoMigrate(&user.CredentialInfo{}, &user.Profile{})

	return &AuthRepository{
		db: db,
	}
}

// SaveUser saves the new user credential
func (r *AuthRepository) SaveUser(c *user.CredentialInfo) {
	if c == nil {
		return
	}
	err := r.db.Transaction(func(tx *gorm.DB) error {
		// do some database operations in the transaction (use 'tx' from this point, not 'db')
		if err := tx.Save(c).Error; err != nil {
			// return any error will rollback
			log.Println("Error saving credentials")
			log.Println(err.Error())
			return err
		}
		// return nil will commit
		return nil
	})
	if err != nil {
		log.Panicln("Failed to insert data\n", err.Error())
	}
}

// FindUser finds the user
func (r *AuthRepository) FindUser(username string) *user.CredentialInfo {

	u := user.CredentialInfo{}
	r.db.Where("User = ?", username).First(&u)
	return &u
}

// FindUser finds the user
func (r *AuthRepository) FindUserByID(id int) *user.CredentialInfo {
	u := user.CredentialInfo{}
	r.db.Where("ID = ?", id).First(&u)
	return &u
}

// ListUSers returns all users
func (r *AuthRepository) ListUSers() (c []user.CredentialInfo) {
	r.db.Find(&c, "")
	return
}
