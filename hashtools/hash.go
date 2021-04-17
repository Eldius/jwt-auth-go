package hashtools

import (
	"crypto/rand"
	"crypto/sha512"
	"io"

	"github.com/Eldius/jwt-auth-go/logger"
	"golang.org/x/crypto/scrypt"
)

const (
	_pwSaltBytes = 32
	_pwHashBytes = 64
)

func HashKey(key string, salt []byte) (hash []byte, err error) {
	h := sha512.New()
	_, err = h.Write([]byte(key))
	if err != nil {
		logger.Logger().WithError(err).Println("Failed to handle key")
		return
	}
	hash, err = Hash(key, salt)
	if err != nil {
		logger.Logger().WithError(err).Println("Failed to handle hash key")
	}
	return
}

// Hash returns the user pass' hash
func Hash(pass string, salt []byte) (hash []byte, err error) {
	hash, err = scrypt.Key([]byte(pass), salt, 1<<14, 8, 1, _pwHashBytes)
	if err != nil {
		logger.Logger().Fatal(err)
	}
	return
}

func Salt() []byte {
	salt := make([]byte, _pwSaltBytes)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		logger.Logger().Fatal(err)
	}

	return salt
}
