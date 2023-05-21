package main

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/aut-cic/id.go/internal/config"
	"github.com/aut-cic/id.go/internal/http"
	"github.com/go-ldap/ldap/v3"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

func main() {
	cfg := config.New()

	l, err := ldap.DialURL(fmt.Sprintf("ldap://%s", cfg.Address))
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	if err := l.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		log.Fatal(err)
	}

	if err := l.Bind(fmt.Sprintf("CN=%s,CN=Users,DC=aku,DC=ac,DC=ir", cfg.Username), cfg.Password); err != nil {
		log.Fatal(err)
	}

	app := echo.New()
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatal(err)
	}

	http.LDAP{
		Conn:   l,
		Logger: logger,
	}.Register(app.Group("/"))

	if err := app.Start(":1373"); err != nil {
		logger.Fatal("http server failed", zap.Error(err))
	}
}
