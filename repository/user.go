package repository

import (
	"log"

	"github.com/Eldius/jwt-auth-go/user"
	"github.com/jinzhu/gorm"
)

// SaveUser saves the new user credential
func SaveUser(c *user.CredentialInfo) {
	if c == nil {
		return
	}
	err := GetDB().Transaction(func(tx *gorm.DB) error {
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
func FindUser(username string) *user.CredentialInfo {

	u := user.CredentialInfo{}
	GetDB().Where("User = ?", username).First(&u)
	return &u
}

// FindUser finds the user
func FindUserByID(id int) *user.CredentialInfo {

	u := user.CredentialInfo{}
	GetDB().Where("ID = ?", id).First(&u)
	return &u
}

// ListUSers returns all users
func ListUSers() (r []user.CredentialInfo) {
	GetDB().Find(&r, "")
	return
}
