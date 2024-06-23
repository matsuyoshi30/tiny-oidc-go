package main

import (
	"embed"
	"io"
	"log"
	"log/slog"
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
	w.Write(tokenSet)
}

func serverError(w http.ResponseWriter, err error) {
	slog.Error(err.Error())
	w.WriteHeader(http.StatusInternalServerError)
}
