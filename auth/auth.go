package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Eldius/jwt-auth-go/config"
	"github.com/Eldius/jwt-auth-go/hashtools"
	"github.com/Eldius/jwt-auth-go/repository"
	"github.com/Eldius/jwt-auth-go/user"
)

const (
	invalidJwtFormat = "auth.jwt.validation.format.invalid"
	invalidJwtSign   = "auth.jwt.validation.sign.invalid"
)

type AuthService struct {
	repo *repository.AuthRepository
}

func NewAuthService() *AuthService {
	return &AuthService{
		repo: repository.NewRepository(),
	}
}

func NewAuthServiceCustom(repo *repository.AuthRepository) *AuthService {
	return &AuthService{
		repo: repo,
	}
}

// ValidatePass validates user credentials
func (s *AuthService) ValidatePass(username string, pass string) (u *user.CredentialInfo, err error) {
	var usr = s.repo.FindUser(username)
	if usr.Hash == nil {
		err = fmt.Errorf("Failed to authenticate user")
		return
	}

	var ph []byte
	ph, err = hashtools.Hash(pass, usr.Salt)
	if err != nil {
		return
	}

	if string(ph) == string(usr.Hash) {
		u = usr
	} else {
		err = fmt.Errorf("Failed to authenticate user")
	}

	return
}

func (s *AuthService) ToJWT(u user.CredentialInfo) (jwt string, err error) {
	// Create a new HMAC by defining the hash type and the key (as byte array)
	header, err := generateHeader()
	if err != nil {
		return
	}

	payload, err := generatePayload(u)
	if err != nil {
		return
	}

	jwtWOSign := fmt.Sprintf("%s.%s", header, payload)
	sign, err := signContent(jwtWOSign)
	if err != nil {
		return
	}
	jwt = fmt.Sprintf("%s.%s", jwtWOSign, sign)
	return
}

func (s *AuthService) FromJWT(jwt string) (u *user.CredentialInfo, err error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		err = fmt.Errorf(invalidJwtFormat)
		return
	}
	sign, err := signContent(fmt.Sprintf("%s.%s", parts[0], parts[1]))
	if err != nil {
		return
	}
	if sign != parts[2] {
		err = fmt.Errorf(invalidJwtSign)
		return
	}

	b, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}

	var tmpData map[string]string
	err = json.Unmarshal([]byte(b), &tmpData)
	if err != nil {
		return
	}

	u = s.repo.FindUser(tmpData["user"])

	return
}

func (s *AuthService) AuthInterceptor(f http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		// TODO remove this before release
		if strings.HasPrefix(authHeader, "Bearer ") {
			jwt := strings.Replace(authHeader, "Bearer ", "", 1)
			u, err := s.FromJWT(jwt)
			if err != nil {
				log.Println(err.Error())
				w.WriteHeader(403)
				return
			}
			ctx := r.Context()
			ctx = context.WithValue(ctx, CurrentUserKey, u)
			r = r.WithContext(ctx)
			f.ServeHTTP(w, r)
		} else {
			w.WriteHeader(403)
		}
	})
}

func (s *AuthService) GetCurrentUser(r *http.Request) *user.CredentialInfo {
	ctx := r.Context()
	return ctx.Value(CurrentUserKey).(*user.CredentialInfo)
}

func (s *AuthService) GetRepository() *repository.AuthRepository {
	return s.repo
}

func generateHeader() (headerStr string, err error) {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerByte, err := json.Marshal(header)
	if err != nil {
		return
	}

	headerStr = base64.StdEncoding.EncodeToString([]byte(headerByte))
	return
}

func generatePayload(u user.CredentialInfo) (payloadStr string, err error) {
	payload := map[string]string{
		"user": u.User,
		"name": u.Name,
	}
	ttl := config.GetDefaultJwtTTL()
	if ttl.Milliseconds() >= 0 {
		payload["expires"] = time.Now().Add(ttl).String()
	}
	payloadByte, err := json.Marshal(payload)
	if err != nil {
		return
	}

	payloadStr = base64.StdEncoding.EncodeToString([]byte(payloadByte))
	return
}

func signContent(content string) (sign string, err error) {
	h := hmac.New(sha256.New, []byte(config.GetJWTSecret()))

	// Write Data to it
	_, err = h.Write([]byte(content))
	if err != nil {
		return
	}
	sign = hex.EncodeToString(h.Sum(nil))

	return
}
