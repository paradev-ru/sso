package config

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"

	"github.com/Sirupsen/logrus"
)

var (
	logLevel           string
	listenAddr         string
	upstreamURLRaw     string
	appPublicURLRaw    string
	gitHubClientID     string
	gitHubClientSecret string
	stateString        string
	authorizedUsers    string
	encryptionKeyRaw   string
	csrfAuthKey        string
)

type Config struct {
	LogLevel           string
	ListenAddr         string
	GitHubClientID     string
	GitHubClientSecret string
	StateString        string
	AuthorizedUsers    string
	EncryptionKeyRaw   string
	EncryptionKey      []byte
	UpstreamURLRaw     string
	AppPublicURLRaw    string
	UpstreamURL        *url.URL
	AppPublicURL       *url.URL
}

func init() {
	flag.StringVar(&logLevel, "log-level", "info", "level which sso should log messages")
	flag.StringVar(&listenAddr, "listen-addr", "", "address and port to listen on")
	flag.StringVar(&upstreamURLRaw, "upstream-url", "", "upstream url")
	flag.StringVar(&appPublicURLRaw, "app-url", "", "app public url")
	flag.StringVar(&gitHubClientID, "github-client-id", "", "github client id")
	flag.StringVar(&gitHubClientSecret, "github-client-secret", "", "github client secret")
	flag.StringVar(&stateString, "state-string", "", "oauth2 state string")
	flag.StringVar(&authorizedUsers, "authorized-users", "", "comma-separated list of users that are authorized to use the app")
	flag.StringVar(&encryptionKeyRaw, "encryption-key", "", "key used for cookie authenticated encryption (32 chars)")
}

func New() (*Config, error) {
	config := &Config{
		ListenAddr: "127.0.0.1:8080",
	}

	config.processEnv()

	config.processFlags()

	if config.LogLevel != "" {
		level, err := logrus.ParseLevel(config.LogLevel)
		if err != nil {
			return nil, err
		}
		logrus.SetLevel(level)
	}

	if config.ListenAddr == "" {
		return nil, errors.New("Missing listen address")
	}
	if config.UpstreamURLRaw == "" {
		return nil, errors.New("Missing upstream url")
	}
	upstreamURL, err := url.Parse(config.UpstreamURLRaw)
	if err != nil {
		return nil, fmt.Errorf("Invalid upstream url: %v", err)
	}
	config.UpstreamURL = upstreamURL
	if config.AppPublicURLRaw == "" {
		return nil, errors.New("Missing application public url")
	}
	appPublicURL, err := url.Parse(config.AppPublicURLRaw)
	if err != nil {
		return nil, fmt.Errorf("Invalid application public url: %v", err)
	}
	config.AppPublicURL = appPublicURL
	if config.GitHubClientID == "" {
		return nil, errors.New("Missing GitHub Client ID")
	}
	if config.GitHubClientSecret == "" {
		return nil, errors.New("Missing GetHub Client Secret")
	}
	if config.StateString == "" {
		return nil, errors.New("Missing oAuth2 state string")
	}
	if config.AuthorizedUsers == "" {
		return nil, errors.New("Missing authorized users")
	}
	if config.EncryptionKeyRaw == "" {
		return nil, errors.New("Missing encryption key")
	}
	if len(config.EncryptionKeyRaw) != 32 {
		return nil, errors.New("Invalid encryption-key: length must be exactly 32 bytes")
	}
	config.EncryptionKey = []byte(config.EncryptionKeyRaw)
	return config, nil
}

func (c *Config) processEnv() {
	listenAddrEnv := os.Getenv("SSO_LISTEND_ADDR")
	if len(listenAddrEnv) > 0 {
		c.ListenAddr = listenAddrEnv
	}
	upstreamURLEnv := os.Getenv("SSO_UPSTREAM_URL")
	if len(upstreamURLEnv) > 0 {
		c.UpstreamURLRaw = upstreamURLEnv
	}
	appPublicURLEnv := os.Getenv("SSO_APP_PUBLIC_URL")
	if len(appPublicURLEnv) > 0 {
		c.AppPublicURLRaw = appPublicURLEnv
	}
	gitHubClientIDEnv := os.Getenv("SSO_GITHUB_CLIENT_ID")
	if len(gitHubClientIDEnv) > 0 {
		c.GitHubClientID = gitHubClientIDEnv
	}
	gitHubClientSecretEnv := os.Getenv("SSO_GITHUB_CLIENT_SECRET")
	if len(gitHubClientSecretEnv) > 0 {
		c.GitHubClientSecret = gitHubClientSecretEnv
	}
	stateStringEnv := os.Getenv("SSO_STATE_STRING")
	if len(stateStringEnv) > 0 {
		c.StateString = stateStringEnv
	}
	authorizedUsersEnv := os.Getenv("SSO_AUTHORIZED_USERS")
	if len(authorizedUsersEnv) > 0 {
		c.AuthorizedUsers = authorizedUsersEnv
	}
	encryptionKeyEnv := os.Getenv("SSO_ENCRYPTION_KEY")
	if len(encryptionKeyEnv) > 0 {
		c.EncryptionKeyRaw = encryptionKeyEnv
	}
}

func (c *Config) processFlags() {
	flag.Visit(c.setConfigFromFlag)
}

func (c *Config) setConfigFromFlag(f *flag.Flag) {
	switch f.Name {
	case "log-level":
		c.LogLevel = logLevel
	case "listen-addr":
		c.ListenAddr = listenAddr
	case "upstream-url":
		c.UpstreamURLRaw = upstreamURLRaw
	case "app-url":
		c.AppPublicURLRaw = appPublicURLRaw
	case "github-client-id":
		c.GitHubClientID = gitHubClientID
	case "github-client-secret":
		c.GitHubClientSecret = gitHubClientSecret
	case "state-string":
		c.StateString = stateString
	case "authorized-users":
		c.AuthorizedUsers = authorizedUsers
	case "encryption-key":
		c.EncryptionKeyRaw = encryptionKeyRaw
	}
}
