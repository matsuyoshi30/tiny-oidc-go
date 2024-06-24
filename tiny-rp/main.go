package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"log/slog"
	"math/big"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

//go:embed index.html
var indexTpl string

func main() {
	http.Handle("GET /{$}", UseMiddlewares(http.HandlerFunc(index), SessionMiddleware()))
	http.Handle("/oidc/callback", UseMiddlewares(http.HandlerFunc(callback), SessionMiddleware()))
	log.Fatal(http.ListenAndServe(":4000", nil))
}

func index(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	nb := make([]byte, 16)
	rand.Read(nb)
	nonce := base64.URLEncoding.EncodeToString(nb)

	session := r.Context().Value(ctxSessionKey).(*session)
	session.values["state"] = state
	session.values["nonce"] = nonce

	t, err := template.New("index").Parse(indexTpl)
	if err != nil {
		serverError(w, err)
		return
	}

	data := struct {
		ClientID     string
		RedirectURI  string
		Scope        string
		ResponseType string
		State        string
		Nonce        string
	}{
		ClientID:     "tiny-client",
		RedirectURI:  "http://localhost:4000/oidc/callback",
		Scope:        "openid",
		ResponseType: "code",
		State:        state,
		Nonce:        nonce,
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		serverError(w, err)
		return
	}

	w.Write(buf.Bytes())
}

func callback(w http.ResponseWriter, r *http.Request) {
	redirect_uri := "http://localhost:4000/oidc/callback"
	queries := r.URL.Query()
	code := queries["code"][0]
	scope := queries["scope"][0]
	state := queries["state"][0]

	session := r.Context().Value(ctxSessionKey).(*session)
	if session.values["state"] != state {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid state}`))
		return
	}

	form := url.Values{}
	form.Add("code", code)
	form.Add("redirect_uri", redirect_uri)
	form.Add("grant_type", "authorization_code")
	form.Add("scope", scope)
	form.Add("client_id", "tiny-client")
	form.Add("client_secret", "c1!3n753cr37")

	req, err := http.NewRequest(http.MethodPost, "http://localhost:3000/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		serverError(w, err)
		return
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		serverError(w, err)
		return
	}
	if res.StatusCode != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(res.StatusCode)
	}
	defer res.Body.Close()
	tokenSet, err := io.ReadAll(res.Body)
	if err != nil {
		serverError(w, err)
		return
	}
	slog.Info(string(tokenSet))

	type Token struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	var token Token
	if err := json.Unmarshal(tokenSet, &token); err != nil {
		serverError(w, err)
		return
	}

	configurationURL := "http://localhost:3000/openid-connect/.well-known/openid-configurations"
	confRes, err := http.Get(configurationURL)
	if err != nil {
		serverError(w, err)
		return
	}
	defer confRes.Body.Close()

	var confResJSON map[string]interface{}
	if err := json.NewDecoder(confRes.Body).Decode(&confResJSON); err != nil {
		serverError(w, err)
		return
	}

	idToken := token.IDToken
	jwksURI := confResJSON["jwks_uri"].(string)
	jwkRes, err := http.Get(jwksURI)
	if err != nil {
		serverError(w, err)
		return
	}
	defer jwkRes.Body.Close()

	b, err := io.ReadAll(jwkRes.Body)
	if err != nil {
		serverError(w, err)
		return
	}

	var jwkSet JWKSet
	if err := json.Unmarshal(b, &jwkSet); err != nil {
		serverError(w, err)
		return
	}
	jwk := jwkSet.Keys[0]
	if jwk.Kty != "RSA" || jwk.Alg != "RS256" || jwk.Use != "sig" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"failed to validate jwk"}`))
		return
	}

	jp, err := decodeToken(idToken)
	if err != nil {
		slog.Warn(err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid token"}`))
		return
	}
	if jp.Nonce != session.values["nonce"] {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid nonce"}`))
		return
	}

	if err := verifyToken(idToken, jwk); err != nil {
		slog.Warn(err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid token"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(tokenSet)
}

/// session

type session struct {
	id      string
	values  map[string]interface{}
	created time.Time
}

type sessionManager struct {
	sessions map[string]*session
	mu       sync.Mutex
	maxAge   time.Duration
}

func newSessionManager(maxAge time.Duration) *sessionManager {
	return &sessionManager{
		sessions: make(map[string]*session),
		maxAge:   maxAge,
	}
}

func (sm *sessionManager) createSession() *session {
	b := make([]byte, 32)
	rand.Read(b)
	id := base64.URLEncoding.EncodeToString(b)
	return &session{
		id:      id,
		values:  make(map[string]interface{}),
		created: time.Now(),
	}
}

func (sm *sessionManager) getSession(id string) *session {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	session, exists := sm.sessions[id]
	if !exists || time.Since(session.created) > sm.maxAge {
		return nil
	}
	return session
}

func (sm *sessionManager) saveSession(session *session) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions[session.id] = session
}

var sm = newSessionManager(30 * time.Minute)

/// middleware

type Middleware func(http.Handler) http.Handler

type contextKey string

func (c contextKey) String() string {
	return fmt.Sprintf("context key: %s", c)
}

var ctxSessionKey = contextKey("session")

func SessionMiddleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var session *session
			cookie, err := r.Cookie("session_id")
			if err != nil || cookie.Value == "" {
				session = sm.createSession()
				http.SetCookie(w, &http.Cookie{
					Name:  "session_id",
					Value: session.id,
					Path:  "/",
				})
			} else {
				session = sm.getSession(cookie.Value)
				if session == nil {
					session = sm.createSession()
					http.SetCookie(w, &http.Cookie{
						Name:  "session_id",
						Value: session.id,
						Path:  "/",
					})
				}
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, ctxSessionKey, session)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)

			sm.saveSession(session)
		})
	}
}

func UseMiddlewares(h http.Handler, middlewares ...Middleware) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
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

type JWTPayload struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Aud   string `json:"aud"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Nonce string `json:"nonce"`
}

func decodeToken(token string) (*JWTPayload, error) {
	tokens := strings.Split(token, ".")
	jpJson, err := base64.RawURLEncoding.DecodeString(tokens[1])
	if err != nil {
		return nil, err
	}

	var jp JWTPayload
	if err := json.Unmarshal([]byte(jpJson), &jp); err != nil {
		return nil, err
	}

	return &jp, nil
}

func verifyToken(token string, jwk JWK) error {
	nb, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return err
	}
	eb, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return err
	}

	var eInt int
	if len(eb) == 3 {
		eInt = int(binary.BigEndian.Uint32(append([]byte{0}, eb...)))
	} else if len(eb) == 4 {
		eInt = int(binary.BigEndian.Uint32(eb))
	} else {
		return fmt.Errorf("unexpected length of 'e': %d", len(eb))
	}

	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: eInt,
	}

	tokens := strings.Split(token, ".")
	if len(tokens) != 3 {
		return fmt.Errorf("unexpected token style")
	}

	eh := tokens[0]
	ep := tokens[1]
	es := tokens[2]

	signTarget := fmt.Sprintf("%s.%s", eh, ep)
	dgst := sha256.Sum256([]byte(signTarget))
	signature, _ := base64.StdEncoding.DecodeString(es)

	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, dgst[:], signature); err != nil {
		return err
	}

	return nil
}

func serverError(w http.ResponseWriter, err error) {
	slog.Error(err.Error())
	w.WriteHeader(http.StatusInternalServerError)
}
