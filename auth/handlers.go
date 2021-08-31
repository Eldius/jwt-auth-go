package auth

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/eldius/jwt-auth-go/config"
	"github.com/eldius/jwt-auth-go/logger"
)

/*
LoginRequest is the model to decode login payload
*/
type LoginRequest struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

/*
NewUserRequest is the model to decode new user request
*/
type NewUserRequest struct {
	User   string `json:"user"`
	Pass   string `json:"pass"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
	Admin  bool   `json:"admin"`
}

/*
ContextKey is the key used to add user data into requests context
*/
type ContextKey string

/*
Handler is the object who will take care of authorization validation
*/
type Handler struct {
	svc *Service
}

const (
	// CurrentUserKey constant for the name used when add user data into request context
	CurrentUserKey ContextKey = "currentUser"
)

/*
NewHandler creates a new handler creating a default service instance
*/
func NewHandler() *Handler {
	return &Handler{
		svc: NewService(),
	}
}

/*
NewHandlerCustom creates a new handler passing your own service instance
*/
func NewHandlerCustom(svc *Service) *Handler {
	return &Handler{
		svc: svc,
	}
}

/*
HandleLogin handles login requests
*/
func (h *Handler) HandleLogin() http.HandlerFunc {
	log := logger.Logger()
	return func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			rw.Header().Add("Content-Type", "application/json")

			var u LoginRequest
			err := json.NewDecoder(r.Body).Decode(&u)
			if err != nil {
				log.Println(err.Error())
				rw.WriteHeader(401)
				return
			}
			log.WithField("test", u).Info("HandleLogin")
			if u.User == "" || u.Pass == "" {
				log.Println(err.Error())
				rw.WriteHeader(401)
				return
			}
			cred, err := h.svc.ValidatePass(u.User, u.Pass)
			if err != nil {
				log.Println(err.Error())
				rw.WriteHeader(401)
				return
			}
			log.Println(cred.User)
			if err != nil {
				log.Println(err.Error())
				rw.WriteHeader(401)
				return
			}

			token, err := h.svc.ToJWT(*cred)
			if err != nil {
				log.Println(err.Error())
				rw.WriteHeader(500)
			}
			rw.WriteHeader(200)
			_ = json.NewEncoder(rw).Encode(&map[string]string{
				"token": token,
			})
		} else {
			rw.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

/*
HandleUser handles new user creation
*/
func (h *Handler) HandleUser() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			h.createNewUser(rw, r)
		} else if r.Method == http.MethodPatch {
			log.Println("// TODO create a change password feature")
			rw.WriteHeader(http.StatusNotImplemented)
		} else {
			rw.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

/*
GetService returns the service used by this handler
*/
func (h *Handler) GetService() *Service {
	return h.svc
}

/*
AuthInterceptor is the interceptor used to validate users
is logged and its login data is valid
*/
func (h *Handler) AuthInterceptor(f http.HandlerFunc) http.Handler {
	return h.svc.AuthInterceptor(f)
}

func (h *Handler) createNewUser(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Add("Content-Type", "application/json")
	var u NewUserRequest
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		log.Println(err.Error())
		rw.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	if _, err := h.svc.CreateNewUser(&NewUser{
		User:   u.User,
		Pass:   u.Pass,
		Name:   u.Name,
		Active: config.GetUserDefaultActive(),
		Admin:  u.Admin,
	}); err != nil {
		log.Println(err.Error())
		rw.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = rw.Write([]byte(err.Error()))
		return
	}
	rw.WriteHeader(http.StatusCreated)
}
