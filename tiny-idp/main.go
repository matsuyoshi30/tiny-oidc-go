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
	"strings"
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
	http.HandleFunc("POST /openid-connect/token", PostToken)

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
		eRes := ACErrorResponse{verr.AuthCodeError}
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

func PostToken(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	code := r.FormValue("code")

	authCode := findAuthCode(code, clientID)
	client := findClient(clientID)

	if terr := validateToken(r, authCode, client); terr != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusBadRequest)
		b, err := json.Marshal(terr)
		if err != nil {
			serverError(w, err)
			return
		}
		w.Write(b)
		return
	}

	now := time.Now()
	authCode.UsedAt = &now
	saveAuthCode(authCode)

	accessToken := buildAccessToken(authCode.UserID)
	saveAccessToken(accessToken)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	res := struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}{
		IDToken:     "dummy-id-token", // TODO: generate JWT
		AccessToken: accessToken.Token,
		TokenType:   "Bearer",
		ExpiresIn:   86400,
	}

	b, err := json.Marshal(res)
	if err != nil {
		serverError(w, err)
		return
	}
	slog.Info(string(b))
	w.Write(b)
}

/// validation

type ACErrorResponse struct {
	Error AuthCodeError
}

type AuthCodeError string

const (
	ACEInvalidRequest          AuthCodeError = "invalid_request"
	ACEUnsupportedResponseType               = "unsupported_response_type"
	ACEInvalidScope                          = "invalid_scope"
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
		return &validateGetAuthError{ACEInvalidRequest, targetResourceOwner}
	}
	if !slices.Contains(validRedirectURIs, redirectURI[0]) {
		return &validateGetAuthError{ACEInvalidRequest, targetResourceOwner}
	}
	if !slices.Contains(validClientIDs, clientID[0]) {
		return &validateGetAuthError{ACEInvalidRequest, targetResourceOwner}
	}

	validResponseTypes := []string{"code"}
	validScopes := []string{"openid"}

	responseType := queries["response_type"]
	scope := queries["scope"]

	if len(responseType) != 1 {
		return &validateGetAuthError{ACEInvalidRequest, targetRedirectURI}
	}
	if len(scope) != 1 {
		return &validateGetAuthError{ACEInvalidRequest, targetRedirectURI}
	}
	if !slices.Contains(validResponseTypes, responseType[0]) {
		return &validateGetAuthError{ACEUnsupportedResponseType, targetRedirectURI}
	}
	if !slices.Contains(validScopes, scope[0]) {
		return &validateGetAuthError{ACEInvalidScope, targetRedirectURI}
	}

	return nil
}

type TErrorResponse struct {
	Error TokenError
}

type TokenError string

const (
	TEInvalidRequest       TokenError = "invalid_request"
	TEInvalidClient                   = "invalid_client"
	TEInvalidGrant                    = "invalid_grant"
	TEUnauthorizedClient              = "unauthorized_client"
	TEUnsupportedGrantType            = "unsupported_grant_type"
	TEInvalidScope                    = "invalid_scope"
)

func validateToken(r *http.Request, authCode *AuthCode, client *Client) *TErrorResponse {
	if len(r.FormValue("client_id")) == 0 {
		return &TErrorResponse{TEInvalidRequest}
	}
	if len(r.FormValue("code")) == 0 {
		return &TErrorResponse{TEInvalidRequest}
	}
	if len(r.FormValue("grant_type")) == 0 {
		return &TErrorResponse{TEInvalidRequest}
	}
	if len(r.FormValue("redirect_uri")) == 0 {
		return &TErrorResponse{TEInvalidRequest}
	}
	if !strings.EqualFold("authorization_code", r.FormValue("grant_type")) {
		return &TErrorResponse{TEUnsupportedGrantType}
	}

	if authCode == nil {
		return &TErrorResponse{TEInvalidGrant}
	}
	if authCode.UsedAt != nil {
		return &TErrorResponse{TEInvalidGrant}
	}
	if authCode.RedirectURI != r.FormValue("redirect_uri") {
		return &TErrorResponse{TEInvalidGrant}
	}

	if client == nil {
		return &TErrorResponse{TEInvalidClient}
	}
	if client.ClientSecret != r.FormValue("client_secret") {
		return &TErrorResponse{TEInvalidClient}
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

func findAuthCode(code string, clientID string) *AuthCode {
	for _, ac := range authCodes {
		if ac.Code == code && ac.ClientID == clientID && ac.ExpiresAt.After(time.Now()) {
			return &ac
		}
	}

	return nil
}

type AccessToken struct {
	Token     string
	ExpiresAt time.Time
	UserID    int
}

func buildAccessToken(userID int) *AccessToken {
	token := randStringRunes(28)
	return &AccessToken{
		Token:     token,
		ExpiresAt: time.Now().Add(time.Hour * 24),
	}
}

func saveAccessToken(at *AccessToken) {
	for i, accessToken := range accessTokens {
		if at.Token == accessToken.Token {
			accessTokens[i] = *at
		}
	}
	accessTokens = append(accessTokens, *at)
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

type Client struct {
	ClientID     string
	ClientSecret string
}

func findClient(clientID string) *Client {
	for _, c := range clients {
		if c.ClientID == clientID {
			return &c
		}
	}

	return nil
}

var ( // DB
	users        []User
	authCodes    []AuthCode
	accessTokens []AccessToken
	clients      []Client
)

func init() {
	users = append(users, User{
		ID:       1,
		Email:    "tiny-idp@example.com",
		Password: "pass",
		ClientID: "tiny-client",
	})
	clients = append(clients, Client{
		ClientID:     "tiny-client",
		ClientSecret: "c1!3n753cr37",
	})
}

func serverError(w http.ResponseWriter, err error) {
	slog.Error(err.Error())
	w.WriteHeader(http.StatusInternalServerError)
}
