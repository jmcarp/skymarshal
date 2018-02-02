package skymarshal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/concourse/atc/db"
	"github.com/coreos/dex/connector/github"
	"github.com/coreos/dex/server"
	"github.com/coreos/dex/storage"
	"github.com/coreos/dex/storage/memory"
	"github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

type Config struct {
	BaseUrl      string
	BaseAuthUrl  string
	SigningKey   *rsa.PrivateKey
	Expiration   time.Duration
	IsTLSEnabled bool
	TeamFactory  db.TeamFactory
}

const stateCookieName = "_concourse_oauth_state"
const authCookieName = "ATC-Authorization"
const csrfHeaderName = "X-Csrf-Token"

const clientId = "concourse"
const clientSecret = "240fe00d63f44eded4260783fdb1674d"
const redirectUri = "http://localhost:8080/auth/callback"
const issuer = "http://localhost:8080/auth"

func NewHandler(config *Config) (http.Handler, error) {

	dexServer, err := NewDexServer()
	if err != nil {
		return nil, err
	}

	loginServer, err := NewLoginServer(config.SigningKey, config.IsTLSEnabled, config.Expiration, config.TeamFactory)
	if err != nil {
		return nil, err
	}

	webMux := http.NewServeMux()
	webMux.HandleFunc("/auth/login", loginServer.handleLogin)
	webMux.HandleFunc("/auth/logout", loginServer.handleLogout)
	webMux.HandleFunc("/auth/callback", loginServer.handleCallback)
	webMux.HandleFunc("/auth/userinfo", loginServer.handleUserInfo)
	webMux.Handle("/auth/", dexServer)
	return webMux, nil
}

func NewDexServer() (*server.Server, error) {

	conf, _ := json.Marshal(github.Config{
		ClientID:     "9eda3e0f2f47af125cf8",
		ClientSecret: "dce4f72f7cac2c0d58f8b4c371b174e91caeac52",
		RedirectURI:  "http://localhost:8080/auth/callback",
		Orgs:         []github.Org{{Name: "concourse"}, {Name: "pivotal-cf"}},
	})

	connectors := []storage.Connector{
		{
			ID:     "github",
			Type:   "github",
			Name:   "github",
			Config: conf,
		},
		{
			ID:   server.LocalConnector,
			Name: "Email",
			Type: server.LocalConnector,
		},
	}

	clients := []storage.Client{
		{
			ID:           clientId,
			Secret:       clientSecret,
			RedirectURIs: []string{redirectUri},
		},
	}

	encrypted, err := bcrypt.GenerateFromPassword([]byte("blah"), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	passwords := []storage.Password{
		{
			Email: "username",
			Hash:  encrypted,
		},
	}

	s := memory.New(nil)
	s = storage.WithStaticClients(s, clients)
	s = storage.WithStaticConnectors(s, connectors)
	s = storage.WithStaticPasswords(s, passwords, nil)

	webConfig := server.WebConfig{
		Dir:    "/Users/pivotal/workspace/concourse/src/github.com/coreos/dex/web",
		Issuer: "auth",
	}

	serverConfig := server.Config{
		SupportedResponseTypes: []string{"code", "token", "id_token"},
		SkipApprovalScreen:     true,
		Issuer:                 issuer,
		Storage:                s,
		Web:                    webConfig,
		Now:                    time.Now,
	}

	return server.NewServer(context.Background(), serverConfig)
}

func NewLoginServer(key *rsa.PrivateKey, isTLSEnabled bool, expiration time.Duration, teamFactory db.TeamFactory) (*loginServer, error) {
	return &loginServer{
		client:       &http.Client{},
		publicKey:    &key.PublicKey,
		privateKey:   key,
		teamFactory:  teamFactory,
		expiration:   expiration,
		isTLSEnabled: isTLSEnabled,
	}, nil
}

type loginServer struct {
	once         sync.Once
	client       *http.Client
	privateKey   *rsa.PrivateKey
	publicKey    *rsa.PublicKey
	provider     *oidc.Provider
	teamFactory  db.TeamFactory
	expiration   time.Duration
	isTLSEnabled bool
}

func (self *loginServer) lazyProvider() (*oidc.Provider, error) {

	var err error

	self.once.Do(func() {
		ctx := oidc.ClientContext(context.Background(), self.client)
		self.provider, err = oidc.NewProvider(ctx, issuer)
	})

	if err != nil {
		return nil, fmt.Errorf("Failed to query provider %q: %v", issuer, err)
	}

	return self.provider, err
}

func (self *loginServer) handleUserInfo(w http.ResponseWriter, r *http.Request) {

	token, err := getJWT(r, self.publicKey)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	json, _ := json.Marshal(token.Claims)

	w.Write(json)
}

func (self *loginServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   authCookieName,
		Path:   "/",
		MaxAge: -1,
	})
}

func (self *loginServer) handleLogin(w http.ResponseWriter, r *http.Request) {

	provider, err := self.lazyProvider()
	if err != nil {
		http.Error(w, "could not query provider", http.StatusInternalServerError)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{"openid", "profile", "email", "offline_access", "groups"},
		RedirectURL:  redirectUri,
	}

	stateToken := encode(&StateToken{
		Redirect: r.FormValue("redirect"),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    stateToken,
		Path:     "/",
		Expires:  time.Now().Add(time.Minute),
		Secure:   self.isTLSEnabled,
		HttpOnly: true,
	})

	authCodeURL := oauth2Config.AuthCodeURL(stateToken, oauth2.AccessTypeOffline)

	http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
}

func (self *loginServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	var (
		err        error
		token      *oauth2.Token
		stateToken string
	)

	provider, err := self.lazyProvider()
	if err != nil {
		http.Error(w, "could not query provider", http.StatusInternalServerError)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectUri,
	}

	ctx := oidc.ClientContext(r.Context(), self.client)

	cookieState, err := r.Cookie(stateCookieName)
	if err != nil {
		http.Error(w, fmt.Sprintf("cookie state failed: %v", err), http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "GET":
		if errMsg := r.FormValue("error"); errMsg != "" {
			http.Error(w, errMsg+": "+r.FormValue("error_description"), http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		if code == "" {
			http.Error(w, fmt.Sprintf("no code in request: %q", r.Form), http.StatusBadRequest)
			return
		}
		if stateToken = cookieState.Value; stateToken != r.FormValue("state") {
			http.Error(w, fmt.Sprintf("expected state %q", stateToken), http.StatusBadRequest)
			return
		}
		token, err = oauth2Config.Exchange(ctx, code)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to get token: %v", err), http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, fmt.Sprintf("method not implemented: %s", r.Method), http.StatusBadRequest)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusInternalServerError)
		return
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientId})
	idToken, err := verifier.Verify(r.Context(), rawIDToken)

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to verify ID token: %v", err), http.StatusInternalServerError)
		return
	}

	var claims json.RawMessage
	idToken.Claims(&claims)

	buff := new(bytes.Buffer)
	json.Indent(buff, []byte(claims), "", "  ")

	// dexToken := buff.String()

	//TODO convert dex token to concourse token
	// blocked on https://github.com/coreos/dex/pull/1176
	teams, err := self.teamFactory.GetTeams()
	if err != nil {
		http.Error(w, "failed to get teams", http.StatusInternalServerError)
		return
	}

	for _, team := range teams {
		for provider, auth := range team.Auth() {
			fmt.Println(provider, auth)
		}
	}

	exp := time.Now().Add(self.expiration)

	csrfToken, err := generateRandomToken()
	if err != nil {
		http.Error(w, "failed to generate csrf token", http.StatusInternalServerError)
		return
	}

	tokenType, signedToken, err := generateAuthToken(self.privateKey, exp, "main", false, csrfToken)
	if err != nil {
		http.Error(w, "failed to generate auth token", http.StatusInternalServerError)
		return
	}

	redirectUrl, err := url.Parse(decode(stateToken).Redirect)
	if err != nil {
		http.Error(w, "invalid redirect", http.StatusBadRequest)
		return
	}

	tokenStr := string(tokenType) + " " + string(signedToken)

	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    tokenStr,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   self.isTLSEnabled,
	})

	http.SetCookie(w, &http.Cookie{
		Name:   stateCookieName,
		Path:   "/",
		MaxAge: -1,
	})

	params := redirectUrl.Query()
	params.Set("token", tokenStr)
	params.Set("csrf_token", csrfToken)
	redirectUrl.RawQuery = params.Encode()

	w.Header().Set(csrfHeaderName, csrfToken)

	http.Redirect(w, r, redirectUrl.String(), http.StatusTemporaryRedirect)
}

type StateToken struct {
	Redirect string `json:"redirect"`
}

func encode(token *StateToken) string {
	json, _ := json.Marshal(token)

	return base64.StdEncoding.EncodeToString(json)
}

func decode(raw string) *StateToken {
	data, _ := base64.StdEncoding.DecodeString(raw)

	var token *StateToken
	json.Unmarshal(data, &token)
	return token
}

func generateRandomToken() (string, error) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)

	if err != nil {
		return "", err
	}

	return hex.EncodeToString(randomBytes), nil
}

func generateAuthToken(key *rsa.PrivateKey, expiration time.Time, teamName string, isAdmin bool, csrf string) (string, string, error) {

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp":      expiration.Unix(),
		"teamName": teamName,
		"isAdmin":  isAdmin,
		"csrf":     csrf,
	})

	signed, err := jwtToken.SignedString(key)
	if err != nil {
		return "", "", err
	}

	return "Bearer", signed, err
}

func getJWT(r *http.Request, publicKey *rsa.PublicKey) (token *jwt.Token, err error) {
	fun := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return publicKey, nil
	}

	if ah := r.Header.Get("Authorization"); ah != "" {
		if len(ah) > 6 && strings.ToUpper(ah[0:6]) == "BEARER" {
			return jwt.Parse(ah[7:], fun)
		}
	}

	return nil, errors.New("unable to parse authorization header")
}
