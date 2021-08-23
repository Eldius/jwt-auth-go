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

type NewUserRequest struct {
	User   string `json:"user"`
	Pass   string `json:"pass"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
	Admin  bool   `json:"admin"`
}

type AuthContextKey string

type AuthHandler struct {
	svc *Service
}

const (
	CurrentUserKey AuthContextKey = "currentUser"
)

func NewAuthHandler() *AuthHandler {
	return &AuthHandler{
		svc: NewService(),
	}
}

func NewAuthHandlerCustom(svc *Service) *AuthHandler {
	return &AuthHandler{
		svc: svc,
	}
}

/*
HandleLogin handles login requests
*/
func (h *AuthHandler) HandleLogin() http.HandlerFunc {
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
		cred, err := h.svc.ValidatePass(u.User, u.Pass)
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

		token, err := h.svc.ToJWT(*cred)
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
func (h *AuthHandler) HandleNewUser() http.HandlerFunc {
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

		if _, err := h.svc.CreateNewUser(&NewUser{
			User:   u.User,
			Pass:   u.Pass,
			Name:   u.Name,
			Active: u.Active,
			Admin:  u.Admin,
		}); err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}

func (h *AuthHandler) GetService() *Service {
	return h.svc
}

func (h *AuthHandler) AuthInterceptor(f http.HandlerFunc) http.Handler {
	return h.svc.AuthInterceptor(f)
}
