package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"slices"
	"time"
)

//go:embed login.html
var loginTpl string

func main() {
	http.HandleFunc("GET /$", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Hello tiny openid provider!"))
	})
	http.HandleFunc("POST /login", Login)
	http.HandleFunc("/openid-connect/auth", GetAuth)

	log.Fatal(http.ListenAndServe(":3000", nil))
}

/// handler

func Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	email := r.FormValue("email")
	password := r.FormValue("password")

	queries := r.URL.Query()
	clientID := queries["client_id"][0]
	redirectURI := queries["redirect_uri"][0]
	scope := queries["scope"][0]
	issuer := "http://localhost:3000"

	if !login(users, email, password) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{error: "unauthorized"}`))
		return
	}
	user, err := findUserByEmail(users, email)
	if err != nil {
		serverError(w, err)
		return
	}
	authCode := buildAuthCode(user.ID, clientID, redirectURI)
	saveAuthCode(authCode)
	w.Header().Set("Location", fmt.Sprintf("%s?code=%s&iss=%s&scope=%s", redirectURI, authCode.Code, issuer, scope))
	w.WriteHeader(http.StatusFound)
}

func GetAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	queries := r.URL.Query()
	clientID := queries["client_id"][0]
	redirectURI := queries["redirect_uri"][0]
	scope := queries["scope"][0]

	if verr := validateGetAuth(queries); verr != nil {
		eRes := ErrorResponse{verr.AuthCodeError}
		if verr.Target == targetRedirectURI {
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			w.Header().Set("Location", fmt.Sprintf("%s?%s", redirectURI, eRes))
			w.WriteHeader(http.StatusFound)
			return
		} else {
			w.WriteHeader(http.StatusBadRequest)
			b, err := json.Marshal(eRes)
			if err != nil {
				serverError(w, err)
				return
			}
			w.Write(b)
			return
		}
	}

	t, err := template.New("login").Parse(loginTpl)
	if err != nil {
		serverError(w, err)
		return
	}

	data := struct {
		ClientID    string
		RedirectURI string
		Scope       string
	}{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		serverError(w, err)
		return
	}

	w.Write(buf.Bytes())
}

/// validation

type ErrorResponse struct {
	Error AuthCodeError
}

type AuthCodeError string

const (
	invalidRequest          AuthCodeError = "invalid_request"
	unsupportedResponseType               = "unsupported_response_type"
	invalidScope                          = "invalid_scope"
)

type ErrorTarget string

const (
	targetResourceOwner ErrorTarget = "resourceOwner"
	targetRedirectURI               = "redirectUri"
)

type validateGetAuthError struct {
	AuthCodeError AuthCodeError
	Target        ErrorTarget
}

func validateGetAuth(queries url.Values) *validateGetAuthError {
	validRedirectURIs := []string{"http://localhost:4000/oidc/callback"}
	validClientIDs := []string{"tiny-client"}

	redirectURI := queries["redirect_uri"]
	clientID := queries["client_id"]

	if len(redirectURI) != 1 || len(clientID) != 1 {
		return &validateGetAuthError{invalidRequest, targetResourceOwner}
	}
	if !slices.Contains(validRedirectURIs, redirectURI[0]) {
		return &validateGetAuthError{invalidRequest, targetResourceOwner}
	}
	if !slices.Contains(validClientIDs, clientID[0]) {
		return &validateGetAuthError{invalidRequest, targetResourceOwner}
	}

	validResponseTypes := []string{"code"}
	validScopes := []string{"openid"}

	responseType := queries["response_type"]
	scope := queries["scope"]

	if len(responseType) != 1 {
		return &validateGetAuthError{invalidRequest, targetRedirectURI}
	}
	if len(scope) != 1 {
		return &validateGetAuthError{invalidRequest, targetRedirectURI}
	}
	if !slices.Contains(validResponseTypes, responseType[0]) {
		return &validateGetAuthError{unsupportedResponseType, targetRedirectURI}
	}
	if !slices.Contains(validScopes, scope[0]) {
		return &validateGetAuthError{invalidScope, targetRedirectURI}
	}

	return nil
}

/// models

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
	ClientID string `json:"clientId"`
}

func findUserByEmail(db []User, email string) (*User, error) {
	for _, u := range db {
		if u.Email == email {
			return &u, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func login(db []User, email string, password string) bool {
	for _, u := range db {
		if u.Email == email && u.Password == password {
			return true
		}
	}
	return false
}

type AuthCode struct {
	Code        string
	UserID      int
	ClientID    string
	ExpiresAt   time.Time
	UsedAt      *time.Time
	RedirectURI string
}

func buildAuthCode(userID int, clientID string, redirectURI string) *AuthCode {
	code := randStringRunes(28)
	return &AuthCode{
		Code:        code,
		UserID:      userID,
		ClientID:    clientID,
		ExpiresAt:   time.Now().Add(time.Minute),
		RedirectURI: redirectURI,
	}
}

func saveAuthCode(ac *AuthCode) {
	for i, authcode := range authCodes {
		if ac.Code == authcode.Code {
			authCodes[i] = *ac
			return
		}
	}
	authCodes = append(authCodes, *ac)
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

var ( // DB
	users     []User
	authCodes []AuthCode
)

func init() {
	users = append(users, User{
		ID:       1,
		Email:    "tiny-idp@example.com",
		Password: "pass",
		ClientID: "tiny-client",
	})
}

func serverError(w http.ResponseWriter, err error) {
	slog.Error(err.Error())
	w.WriteHeader(http.StatusInternalServerError)
}
