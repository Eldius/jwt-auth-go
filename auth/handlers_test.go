package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

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
	viper.SetDefault("auth.jwt.secret", "uuid.New().String()")
	viper.SetDefault("auth.user.default.active", true)
	if err := viper.ReadInConfig(); err == nil {
		log.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func TestAuthHandleUserRequestCreated(t *testing.T) {
	h := NewHandler()
	s := httptest.NewServer(h.HandleUser())
	defer s.Close()
	res, err := http.Post(s.URL, "application/json", bytes.NewBuffer([]byte(validUserPayload)))
	if err != nil {
		t.Errorf("Failed to execute request")
	}

	if res.StatusCode != http.StatusCreated {
		t.Errorf("Should return status code 204 (created), but was '%s'", res.Status)
	}
}

func TestAuthHandleUserUnprocessableNoUsername(t *testing.T) {
	h := NewHandler()
	s := httptest.NewServer(h.HandleUser())
	defer s.Close()
	res, err := http.Post(s.URL, "application/json", bytes.NewBuffer([]byte(userlessUserPayload)))
	if err != nil {
		t.Errorf("Failed to execute request")
	}

	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("Should return status code 422 (created), but was '%s'", res.Status)
	}
}

func TestAuthHandleUserUnprocessableNoPassword(t *testing.T) {
	h := NewHandler()
	s := httptest.NewServer(h.HandleUser())
	defer s.Close()
	res, err := http.Post(s.URL, "application/json", bytes.NewBuffer([]byte(passlessUserPayload)))
	if err != nil {
		t.Errorf("Failed to execute request")
	}

	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("Should return status code 422 (created), but was '%s'", res.Status)
	}
}

func TestAuthHandleUserUnprocessableInvalidActiveAttribute(t *testing.T) {
	h := NewHandler()
	s := httptest.NewServer(h.HandleUser())
	defer s.Close()
	res, err := http.Post(s.URL, "application/json", bytes.NewBuffer([]byte(invalidActiveUserPayload)))
	if err != nil {
		t.Errorf("Failed to execute request")
	}

	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("Should return status code 422 (created), but was '%s'", res.Status)
	}
}

func TestAuthHandleUserGet(t *testing.T) {
	h := NewHandler()
	s := httptest.NewServer(h.HandleUser())
	defer s.Close()
	res, err := http.Get(s.URL)
	if err != nil {
		t.Errorf("Failed to execute request")
	}

	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Should return status code 415 (Method Not Allowed), but was '%s'", res.Status)
	}
}

func TestAuthHandleUserPatch(t *testing.T) {
	h := NewHandler()
	s := httptest.NewServer(h.HandleUser())
	defer s.Close()
	r := bytes.NewReader([]byte(`{}`))
	req, err := http.NewRequest(http.MethodPatch, s.URL, r)
	if err != nil {
		t.Errorf("Error creating patch request: '%s'", err.Error())
	}
	c := http.Client{}
	res, err := c.Do(req)
	if err != nil {
		t.Errorf("Failed to execute request")
	}

	if res.StatusCode != http.StatusNotImplemented {
		t.Errorf("Should return status code 501 (Not Implemented), but was '%s'", res.Status)
	}
}

func TestLogin(t *testing.T) {
	h := NewHandler()

	usrN := "test.user.001"
	usrP := "test-strong-pass-001"

	setupUser(t, usrN, usrP, h.svc)

	l := LoginRequest{
		User: usrN,
		Pass: usrP,
	}
	body, err := json.Marshal(l)
	if err != nil {
		t.Logf("Failed to encode login data: %s", err.Error())
	}
	svc := h.GetService()
	repo := svc.GetRepository()
	u := repo.FindUser(usrN)
	t.Logf("user: %v", *u)
	s := httptest.NewServer(h.HandleLogin())
	defer s.Close()

	loginPayload := string(body)
	t.Logf("login: %s", loginPayload)

	res, err := http.Post(s.URL, "application/json", bytes.NewReader([]byte(loginPayload)))
	if err != nil {
		t.Errorf("Failed to execute request: %v", err)
		t.FailNow()
	}

	if res.StatusCode != http.StatusOK {
		t.Errorf("Should return 200 (OK), but was '%s'", res.Status)
	}
}

func TestAuthInterceptorSuccess(t *testing.T) {
	h := NewHandler()

	usrN := "test.user.002"
	usrP := "test-strong-pass-002"

	setupUser(t, usrN, usrP, h.svc)

	svc := h.GetService()
	r := h.svc.repo
	c := r.FindUser(usrN)

	jwt, err := svc.ToJWT(*c)
	if err != nil {
		t.Errorf("Failed to create JWT string: %s", err.Error())
		t.FailNow()
	}

	s := httptest.NewServer(h.AuthInterceptor(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}))
	defer s.Close()

	req, err := http.NewRequest(http.MethodPost, s.URL, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Errorf("Failed to create request: %s", err.Error())
		t.FailNow()
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", jwt))
	req.Header.Add("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Failed to execute request: %v", err)
		t.FailNow()
	}

	if res.StatusCode != http.StatusNoContent {
		t.Errorf("Should return 204 (No Content), but was '%s'", res.Status)
	}
}

func TestAuthInterceptorInvalidJWTToken(t *testing.T) {
	h := NewHandler()

	s := httptest.NewServer(h.AuthInterceptor(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}))
	defer s.Close()

	req, err := http.NewRequest(http.MethodPost, s.URL, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Errorf("Failed to create request: %s", err.Error())
		t.FailNow()
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "ABC123"))
	req.Header.Add("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Failed to execute request: %v", err)
		t.FailNow()
	}

	if res.StatusCode != http.StatusForbidden {
		t.Errorf("Should return 403 (Forbidden), but was '%s'", res.Status)
	}
}

func TestAuthInterceptorWithoutJWTToken(t *testing.T) {
	h := NewHandler()

	s := httptest.NewServer(h.AuthInterceptor(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}))
	defer s.Close()

	req, err := http.NewRequest(http.MethodPost, s.URL, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Errorf("Failed to create request: %s", err.Error())
		t.FailNow()
	}

	req.Header.Add("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Failed to execute request: %v", err)
		t.FailNow()
	}

	if res.StatusCode != http.StatusForbidden {
		t.Errorf("Should return 403 (Forbidden), but was '%s'", res.Status)
	}
}

func setupUser(t *testing.T, usrN string, usrP string, svc *Service) {
	_, err := svc.CreateNewUser(&NewUser{
		User:   usrN,
		Pass:   usrP,
		Name:   usrN,
		Admin:  true,
		Active: true,
	})
	if err != nil {
		t.Errorf("Failed to create test user: %v", err)
		t.FailNow()
	}

}
