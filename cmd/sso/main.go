package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/leominov/sso"
	"github.com/leominov/sso/config"
)

var (
	printVersion bool
)

func init() {
	flag.BoolVar(&printVersion, "version", false, "print version and exit")
}

func main() {
	flag.Parse()
	if printVersion {
		fmt.Printf("sso %s\n", sso.Version)
		os.Exit(0)
	}
	cfg, err := config.New()
	if err != nil {
		logrus.Error(err)
		os.Exit(1)
	}
	logrus.Info("Starting sso...")
	sso := sso.New(cfg)
	s := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: sso,
	}
	logrus.Panic(s.ListenAndServe())
}
