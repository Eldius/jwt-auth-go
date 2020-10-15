package auth

import (
	"encoding/json"
	"log"
	"net/http"
)

type LoginRequest struct {
	User string `json:"user"`
	Pass string `json:"pass"`
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
