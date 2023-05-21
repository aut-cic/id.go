package main

import (
	"log"

	"github.com/aut-cic/id.go/internal/config"
	"github.com/aut-cic/id.go/internal/http"
	"github.com/aut-cic/id.go/internal/ldap"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

func main() {
	cfg := config.New()

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatal(err)
	}

	m, err := ldap.New(cfg.LDAP, logger.Named("ldap"))
	if err != nil {
		log.Fatal(err)
	}

	app := echo.New()

	http.LDAP{
		Manager: m,
		Logger:  logger.Named("http.ldap"),
	}.Register(app.Group(""))

	if err := app.Start(":1373"); err != nil {
		logger.Fatal("http server failed", zap.Error(err))
	}
}
