package auth

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/Eldius/jwt-auth-go/config"
	"github.com/Eldius/jwt-auth-go/repository"
	"github.com/Eldius/jwt-auth-go/user"
	"github.com/spf13/viper"
)

var (
	tmpDir string
)

func init() {
	//viper.SetConfigFile("../config/samples/auth-server-sqlite3.yml")
	var err error
	tmpDir, err = ioutil.TempDir("", "auth-server")
	if err != nil {
		log.Println("Failed to setup temp database")
		log.Fatal(err.Error())
	}
	os.RemoveAll(tmpDir)
	if err := os.MkdirAll(tmpDir, os.ModePerm); err != nil {
		log.Panic("Failed to create temp dir for tests.")
	}
	viper.SetDefault("auth.database.url", fmt.Sprintf("%s/test.db", tmpDir))
	viper.SetDefault("auth.database.engine", "sqlite3")
	log.Println("db file:", config.GetDBURL())

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func TestValidatePass(t *testing.T) {
	username := "user"
	passwd := "pass"
	u, err := user.NewCredentials(username, passwd)
	if err != nil {
		t.Errorf("Failed to prepare test user:\n%s", err.Error())
	}

	r := repository.NewRepository()
	svc := NewAuthServiceCustom(r)

	r.SaveUser(&u)

	c, err := svc.ValidatePass(username, passwd)
	if err != nil {
		t.Error(err)
	}

	if c == nil {
		t.Errorf("Failed to validate user (returned nil value)")
	}

}

func TestValidatePassInvalidCredentials(t *testing.T) {
	username := "user1"
	passwd := "pass1"
	u, err := user.NewCredentials(username, passwd)
	if err != nil {
		t.Errorf("Failed to prepare test user:\n%s", err.Error())
	}

	r := repository.NewRepository()
	svc := NewAuthServiceCustom(r)

	r.SaveUser(&u)

	c, err := svc.ValidatePass(username, "pass")
	if err == nil {
		t.Error("Should return an error in login process")
	}

	if c != nil {
		t.Errorf("Failed to validate user (returned nil value)")
	}

}

func TestValidatePassUserNotFound(t *testing.T) {
	username := "user2"
	passwd := "pass1"

	svc := NewAuthService()

	c, err := svc.ValidatePass(username, passwd)
	if err == nil {
		t.Error("Should return an error")
	}

	if c != nil {
		t.Errorf("Failed to validate user (returned nil value)")
	}

}

func TestToJWT(t *testing.T) {
	u, err := user.NewCredentials("myUser", "myPass")
	if err != nil {
		t.Errorf("Failed to create the test user\n%s", err.Error())
	}
	svc := NewAuthService()

	token, err := svc.ToJWT(u)
	if err != nil {
		t.Errorf("Failed to create token\n%s", err.Error())
	}
	t.Logf("token: %s", token)

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("Should return 3 parts separated by dot (.), but returned %d", len(parts))
	}
}
