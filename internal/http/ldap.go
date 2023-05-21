package http

import (
	"errors"
	"net/http"

	"github.com/aut-cic/id.go/internal/ldap"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type LDAP struct {
	Manager ldap.Manager
	Logger  *zap.Logger
}

func (l LDAP) ChangePassword(c echo.Context) error {
	validate := validator.New()

	username := c.QueryParam("un")
	password := c.QueryParam("pw")

	if err := validate.Var(username, "required,ascii"); err != nil {
		return echo.ErrBadRequest
	}

	if err := validate.Var(password, "required,ascii"); err != nil {
		return echo.ErrBadRequest
	}

	if err := l.Manager.ChangePassword(username, password); err != nil {
		if errors.Is(err, ldap.ErrUserNotFound) {
			l.Logger.Error("user does not exist", zap.String("username", username))

			return echo.ErrNotFound
		}

		l.Logger.Error("change password using ldap failed", zap.Error(err))

		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, username)
}

func (l LDAP) Register(g *echo.Group) {
	g.GET("/change-password", l.ChangePassword)
}
