package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
)

//go:embed index.html
var index embed.FS

func main() {
	http.Handle("/", http.FileServer(http.FS(index)))
	http.HandleFunc("/oidc/callback", callback)
	log.Fatal(http.ListenAndServe(":4000", nil))
}

func callback(w http.ResponseWriter, r *http.Request) {
	redirect_uri := "http://localhost:4000/oidc/callback"
	queries := r.URL.Query()
	code := queries["code"][0]
	scope := queries["scope"][0]

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
