package auth

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/viper"
)

//func TestTest(t *testing.T) {
//	data, err := base64.RawStdEncoding.DecodeString("eyJuYW1lIjoiVGVzdCB1c2VyIiwidXNlciI6InVzZXIifQ==")
//	if err != nil {
//		t.Error(err.Error())
//	}
//	log.Println(string(data))
//}

const (
	validUserPayload = `{
		"user":"valid.user",
		"pass":"pass",
		"name":"name",
		"active":true,
		"admin":true
	}`
	userlessUserPayload = `{
		"pass":"pass",
		"name":"name",
		"active":true,
		"admin":true
	}`
	passlessUserPayload = `{
		"user":"valid.user1",
		"name":"name",
		"active":true,
		"admin":true
	}`
	invalidActiveUserPayload = `{
		"user":"valid.user2",
		"name":"name",
		"active":active,
		"admin":true
	}`
)

func init() {
	tmp, err := ioutil.TempDir("", "jwt-test")
	if err != nil {
		panic(err.Error())
	}
	viper.SetDefault("auth.database.url", tmp+"/test.db")
	viper.SetDefault("auth.database.engine", "sqlite3")
	viper.SetDefault("auth.user.pattern", "^[a-zA-Z0-9\\._-]*$")
	viper.SetDefault("auth.pass.pattern", "^[a-zA-Z0-9\\._-]*$")
	viper.SetDefault("auth.jwt.secret", uuid.New().String())
	viper.SetDefault("auth.user.default.active", true)
	if err := viper.ReadInConfig(); err == nil {
		log.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func TestAuthRequestCreated(t *testing.T) {
	h := NewHandler()
	s := httptest.NewServer(h.HandleNewUser())
	defer s.Close()
	res, err := http.Post(s.URL, "application/json", bytes.NewBuffer([]byte(validUserPayload)))
	if err != nil {
		t.Errorf("Failed to execute request")
	}

	if res.StatusCode != http.StatusCreated {
		t.Errorf("Should return status code 204 (created), but was '%s'", res.Status)
	}
}

func TestAuthUnprocessableNoUsername(t *testing.T) {
	h := NewHandler()
	s := httptest.NewServer(h.HandleNewUser())
	defer s.Close()
	res, err := http.Post(s.URL, "application/json", bytes.NewBuffer([]byte(userlessUserPayload)))
	if err != nil {
		t.Errorf("Failed to execute request")
	}

	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("Should return status code 422 (created), but was '%s'", res.Status)
	}
}

func TestAuthUnprocessableNoPassword(t *testing.T) {
	h := NewHandler()
	s := httptest.NewServer(h.HandleNewUser())
	defer s.Close()
	res, err := http.Post(s.URL, "application/json", bytes.NewBuffer([]byte(passlessUserPayload)))
	if err != nil {
		t.Errorf("Failed to execute request")
	}

	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("Should return status code 422 (created), but was '%s'", res.Status)
	}
}

func TestAuthUnprocessableInvalidActiveAttribute(t *testing.T) {
	h := NewHandler()
	s := httptest.NewServer(h.HandleNewUser())
	defer s.Close()
	res, err := http.Post(s.URL, "application/json", bytes.NewBuffer([]byte(invalidActiveUserPayload)))
	if err != nil {
		t.Errorf("Failed to execute request")
	}

	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("Should return status code 422 (created), but was '%s'", res.Status)
	}
}
