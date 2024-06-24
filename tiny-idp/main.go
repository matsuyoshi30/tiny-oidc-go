package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"log/slog"
	"math/big"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

//go:embed login.html
var loginTpl string

func main() {
	http.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Hello tiny openid provider!"))
	})
	http.HandleFunc("POST /login", Login)
	http.HandleFunc("/openid-connect/auth", GetAuth)
	http.HandleFunc("POST /openid-connect/token", PostToken)
	http.HandleFunc("POST /openid-connect/introspect", PostIntrospect)
	http.HandleFunc("GET /openid-connect/jwks", GetJWKs)
	http.HandleFunc("GET /openid-connect/.well-known/openid-configurations", GetConfiguration)

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
	state := queries["state"][0]
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
	if len(queries["nonce"]) == 1 {
		authCode.setNonce(queries["nonce"][0])
	}
	saveAuthCode(authCode)
	w.Header().Set("Location", fmt.Sprintf("%s?code=%s&iss=%s&scope=%s&state=%s", redirectURI, authCode.Code, issuer, scope, state))
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
	state := queries["state"][0]
	nonce := queries["nonce"][0]

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
		State       string
		Nonce       string
	}{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
		State:       state,
		Nonce:       nonce,
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
		IDToken:     generateJWT("http://localhost:3000", "tiny-client", time.Hour*24, authCode.Nonce),
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

func PostIntrospect(w http.ResponseWriter, r *http.Request) {
	accessToken := r.FormValue("token")
	foundToken := findAccessToken(accessToken)

	w.Header().Set("Content-Type", "application/json")
	if foundToken == nil || foundToken.ExpiresAt.Before(time.Now()) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"active":false}`))
		return
	}
	w.Write([]byte(`{"active":true}`))
}

func GetJWKs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	jwk := generateJWK()
	jwk.Kid = "2024-06-23"
	jwk.Alg = "RS256"
	jwk.Use = "sig"

	if jwk.Kty == "" {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"failed to generate jwk"}`))
		return
	}

	jwkSet := JWKSet{
		Keys: []JWK{*jwk},
	}
	b, err := json.Marshal(jwkSet)
	if err != nil {
		serverError(w, err)
		return
	}
	w.Write(b)
}

func GetConfiguration(w http.ResponseWriter, r *http.Request) {
	res := struct {
		Issuer                            string   `json:"issuer"`
		AuthorizationEndpoint             string   `json:"authorization_endpoint"`
		TokenEndpoint                     string   `json:"token_endpoint"`
		JWKsURI                           string   `json:"jwks_uri"`
		ResponseTypesSupported            []string `json:"response_types_supported"`
		SubjectTypesSupported             []string `json:"subject_types_supported"`
		IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
		ScopesSupported                   []string `json:"scopes_supported"`
		TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
		ClaimsSupported                   []string `json:"claims_supported"`
	}{
		Issuer:                            "http://localhost:3000/openid-connect",
		AuthorizationEndpoint:             "http://localhost:3000/openid-connect/auth",
		TokenEndpoint:                     "http://localhost:3000/openid-connect/token",
		JWKsURI:                           "http://localhost:3000/openid-connect/jwks",
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   []string{"openid"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		ClaimsSupported:                   []string{"sub", "iss"},
	}

	b, err := json.Marshal(res)
	if err != nil {
		serverError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
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
	state := queries["state"]
	nonce := queries["nonce"]

	if len(redirectURI) != 1 || len(clientID) != 1 || len(state) != 1 || len(nonce) != 1 {
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
	Nonce       string
}

func (ac *AuthCode) setNonce(nonce string) {
	ac.Nonce = nonce
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

func findAccessToken(accessToken string) *AccessToken {
	for _, ac := range accessTokens {
		if ac.Token == accessToken {
			return &ac
		}
	}

	return nil
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

/// JWT

type JWTPayload struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Aud   string `json:"aud"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Nonce string `json:"nonce"`
}

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

var privateKey *rsa.PrivateKey

func generateJWT(iss string, aud string, exp time.Duration, nonce string) string {
	header := JWTHeader{
		Alg: "RS256",
		Typ: "JWT",
		Kid: "2024-06-23",
	}
	hb, err := json.Marshal(header)
	if err != nil {
		panic(err)
	}
	eh := base64.RawURLEncoding.EncodeToString(hb)

	now := time.Now()

	payload := JWTPayload{
		Iss:   iss,
		Sub:   randStringRunes(14),
		Aud:   aud,
		Iat:   now.Unix(),
		Exp:   now.Add(exp).Unix(),
		Nonce: nonce,
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	ep := base64.RawURLEncoding.EncodeToString(pb)

	signTarget := fmt.Sprintf("%s.%s", eh, ep)
	signature := sign(signTarget)

	return fmt.Sprintf("%s.%s", signTarget, signature)
}

func sign(target string) string {
	dgst := sha256.Sum256([]byte(target))
	signature, err := privateKey.Sign(nil, dgst[:], crypto.SHA256)
	if err != nil {
		panic(err)
	}

	return string(base64.StdEncoding.EncodeToString(signature))
}

type JWK struct {
	Kty    string   `json:"kty,omitempty"`
	Use    string   `json:"use,omitempty"`
	Kid    string   `json:"kid,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
	Alg    string   `json:"alg,omitempty"`
	X5u    string   `json:"x5u,omitempty"`
	X5c    string   `json:"x5c,omitempty"`
	X5t    string   `json:"x5t,omitempty"`
	N      string   `json:"n,omitempty"`
	E      string   `json:"e,omitempty"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

var publicKey *rsa.PublicKey

func generateJWK() *JWK {
	return &JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}
}

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

	pemPriv, err := os.Open("./tiny_idp_private.pem")
	if err != nil {
		panic(err)
	}
	privPEM, err := io.ReadAll(pemPriv)
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(privPEM)
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	privateKey = privKey.(*rsa.PrivateKey)

	pemPub, err := os.Open("./tiny_idp_public.pem")
	if err != nil {
		panic(err)
	}
	pubPEM, err := io.ReadAll(pemPub)
	if err != nil {
		panic(err)
	}
	block, _ = pem.Decode(pubPEM)
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	publicKey = pubKey.(*rsa.PublicKey)
}

func serverError(w http.ResponseWriter, err error) {
	slog.Error(err.Error())
	w.WriteHeader(http.StatusInternalServerError)
}
