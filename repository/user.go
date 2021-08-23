package repository

import (
	"github.com/eldius/jwt-auth-go/config"
	"github.com/eldius/jwt-auth-go/logger"
	"github.com/eldius/jwt-auth-go/user"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"
)

var (
	log = logger.Logger()
)

type AuthRepository struct {
	db *gorm.DB
}

func NewRepository() *AuthRepository {
	db, err := gorm.Open(GetDialect())
	if err != nil {
		panic("failed to connect database")
	}
	if config.GetDBLogQueries() {
		db.Logger.LogMode(glogger.Info)
	}
	_ = db.AutoMigrate(&user.CredentialInfo{}, &user.Profile{})

	return &AuthRepository{
		db: db,
	}
}

func NewRepositoryCustom(db *gorm.DB) *AuthRepository {
	_ = db.AutoMigrate(&user.CredentialInfo{}, &user.Profile{})

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
		log.WithError(err).Error("Failed to insert data\n", err.Error())
	}
}

// FindUser finds the user
func (r *AuthRepository) FindUser(username string) *user.CredentialInfo {

	var u *user.CredentialInfo
	//r.db.Where("User = ?", username).First(&u)
	tx := r.db.Where("User = ?", username).First(&u)
	if tx.Error != nil {
		log.WithError(tx.Error).Info("FindUser")
		return nil
	}
	return u
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

func GetDialect() gorm.Dialector {
	switch config.GetDBEngine() {
	case "sqlite":
		return sqlite.Open(config.GetDBURL())
	case "mysql", "mariadb":
		return mysql.Open(config.GetDBURL())
	default:
		return sqlite.Open(config.GetDBURL())
	}
}
