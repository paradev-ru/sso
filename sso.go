package sso

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/leominov/sso/config"

	"github.com/Sirupsen/logrus"
	githubcli "github.com/google/go-github/github"
	"github.com/vulcand/oxy/forward"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type SSO struct {
	c             *config.Config
	CookieName    string
	HeaderName    string
	encryptionKey []byte
	oAuthConf     *oauth2.Config
	Authorized    func(User) (bool, error)
}

type User struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Login      string `json:"login"`
	Email      string `json:"email"`
	GravatarID string `json:"gravatar_id"`
}

type State struct {
	User  User   `json:"user"`
	Token string `json:"token"`
}

func New(config *config.Config) *SSO {
	conf := &oauth2.Config{
		ClientID:     config.GitHubClientID,
		ClientSecret: config.GitHubClientSecret,
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}
	authorized := make(map[string]bool)
	for _, login := range strings.Split(config.AuthorizedUsers, ",") {
		authorized[strings.Trim(login, " ")] = true
	}
	logrus.Infof("Authorized users: %v", authorized)
	return &SSO{
		c:             config,
		oAuthConf:     conf,
		CookieName:    "paradev.sso",
		HeaderName:    "Paradev-State",
		encryptionKey: []byte(config.EncryptionKey),
		Authorized: func(u User) (bool, error) {
			return authorized[u.Login], nil
		},
	}
}

func (s *SSO) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sso/login", s.handleLogin)
	mux.HandleFunc("/sso/callback", s.handleCallback)
	mux.HandleFunc("/sso/logout", s.handleLogout)
	mux.HandleFunc("/", s.handleRequest)
	mux.ServeHTTP(w, r)
}

func (s *SSO) handleLogout(w http.ResponseWriter, req *http.Request) {
	s.setLogoutCookie(w)
	w.Write([]byte("logged out"))
}

func (s *SSO) handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state != s.c.StateString {
		http.Error(w, fmt.Sprintf("Invalid oAuth state, got '%s'", state), 500)
		return
	}
	code := r.FormValue("code")
	token, err := s.oAuthConf.Exchange(oauth2.NoContext, code)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	oAuthClient := s.oAuthConf.Client(oauth2.NoContext, token)
	gitHubClient := githubcli.NewClient(oAuthClient)
	user, _, err := gitHubClient.Users.Get("")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	u := User{
		ID:    *user.ID,
		Login: *user.Login,
	}
	if user.Name != nil {
		u.Name = *user.Name
	}
	if user.Email != nil {
		u.Email = *user.Email
	}
	if user.GravatarID != nil {
		u.GravatarID = *user.GravatarID
	}
	ok, err := s.Authorized(u)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !ok {
		http.Error(w, fmt.Sprintf("Access denied for user %s", u.Login), 403)
		return
	}
	userState := &State{
		User:  u,
		Token: token.AccessToken,
	}
	b, err := json.Marshal(userState)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	encryptedCookie, nonce, err := encrypt(b, s.c.EncryptionKey)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	encryptedCookie = append(nonce, encryptedCookie...)
	encodedCookie := base64.StdEncoding.EncodeToString(encryptedCookie)
	http.SetCookie(w, &http.Cookie{
		Name:    s.CookieName,
		Value:   encodedCookie,
		Path:    "/",
		Domain:  domainFromHost(s.c.AppPublicURL.Host),
		Expires: time.Now().Add(365 * 24 * time.Hour),
	})
	logrus.Info("Cookies set, redirecting back")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *SSO) handleRequest(w http.ResponseWriter, r *http.Request) {
	state, err := s.stateFromRequest(r)
	if err != nil && err != http.ErrNoCookie {
		s.setLogoutCookie(w)
		http.Error(w, err.Error(), 500)
		return
	}
	if state != nil {
		s.handleProxy(w, r, state)
		return
	}
	s.handleLogin(w, r)
}

func (s *SSO) handleProxy(w http.ResponseWriter, r *http.Request, state *State) {
	b, err := json.Marshal(state)
	if err != nil {
		logrus.Error(err)
		http.Error(w, err.Error(), 500)
		return
	}
	r.URL.Scheme = s.c.UpstreamURL.Scheme
	r.URL.Host = s.c.UpstreamURL.Host
	r.Header.Add(s.HeaderName, string(b))
	fwd, err := forward.New()
	if err != nil {
		logrus.Error(err)
		http.Error(w, err.Error(), 500)
		return
	}
	fwd.ServeHTTP(w, r)
}

func (s *SSO) handleLogin(w http.ResponseWriter, r *http.Request) {
	url := s.oAuthConf.AuthCodeURL(s.c.StateString, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (s *SSO) setLogoutCookie(w http.ResponseWriter) {
	cookieNames := []string{s.CookieName, "_gorilla_csrf"}
	for _, cookieName := range cookieNames {
		http.SetCookie(w, &http.Cookie{
			Name:    cookieName,
			Value:   "",
			Path:    "/",
			Domain:  domainFromHost(s.c.AppPublicURL.Host),
			Expires: time.Date(1970, time.January, 1, 1, 0, 0, 0, time.UTC),
		})
	}
}

func (s *SSO) stateFromRequest(req *http.Request) (*State, error) {
	cookie, err := req.Cookie(s.CookieName)
	if err == http.ErrNoCookie {
		return nil, http.ErrNoCookie
	}
	if err != nil {
		return nil, err
	}
	decodedCookie, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, err
	}
	encryptedCookie := []byte(decodedCookie)
	nonce := encryptedCookie[:12]
	encryptedCookie = encryptedCookie[12:]
	if len(nonce) != 12 {
		return nil, errors.New("Nonce must be 12 characters in length")
	}
	if len(encryptedCookie) == 0 {
		return nil, errors.New("Encrypted Cookie missing")
	}
	b, err := decrypt(encryptedCookie, nonce, s.c.EncryptionKey)
	if err != nil {
		return nil, err
	}
	var state *State
	err = json.NewDecoder(bytes.NewReader(b)).Decode(&state)
	if err != nil {
		return nil, err
	}
	return state, nil
}
