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

	m := ldap.Manager{
		Address:  cfg.Address,
		Username: cfg.Username,
		Password: cfg.Password,
	}

	app := echo.New()
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatal(err)
	}

	http.LDAP{
		Manager: m,
		Logger:  logger,
	}.Register(app.Group(""))

	if err := app.Start(":1373"); err != nil {
		logger.Fatal("http server failed", zap.Error(err))
	}
}
