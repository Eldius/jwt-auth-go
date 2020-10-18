package auth

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/Eldius/jwt-auth-go/config"
	"github.com/Eldius/jwt-auth-go/repository"
	"github.com/Eldius/jwt-auth-go/user"
)

type LoginRequest struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type NewUserRequest struct {
	User   string `json:"user"`
	Pass   string `json:"pass"`
	Name   string `json:"name"`
	Active bool `json:"active"`
	Admin  bool `json:"admin"`
}

type AuthContextKey string

const (
	CurrentUserKey AuthContextKey = "currentUser"
)

/*
HandleLogin handles login requests
*/
func HandleLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//w.Header().Add("Content-Type", "application/json")
		w.Header().Add("Content-Type", "application/json")
		var u LoginRequest
		err := json.NewDecoder(r.Body).Decode(&u)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(401)
			return
		}
		if u.User == "" || u.Pass == "" {
			log.Println(err.Error())
			w.WriteHeader(401)
			return
		}
		cred, err := ValidatePass(u.User, u.Pass)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(401)
			return
		}
		log.Println(cred.User)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(401)
			return
		}

		token, err := ToJWT(*cred)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(500)
		}
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(&map[string]string{
			"token": token,
		})
	}
}

/*
HandleNewUser handles new user creation
*/
func HandleNewUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		w.Header().Add("Content-Type", "application/json")
		var u NewUserRequest
		err := json.NewDecoder(r.Body).Decode(&u)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}

		c, err := toCredentials(&u)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		repository.SaveUser(c)
		w.WriteHeader(http.StatusCreated)
	}
}

func toCredentials(u *NewUserRequest) (*user.CredentialInfo, error) {
		c, err := user.NewCredentials(u.User, u.Pass)
		if err != nil {
			return nil, err
		}
		c.Name = u.Name
		c.Admin = u.Admin
		c.Active = config.GetUserDefaultActive()
		return &c, nil
}
