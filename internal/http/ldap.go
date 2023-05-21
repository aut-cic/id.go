package http

import (
	"fmt"
	"log"
	"net/http"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"golang.org/x/text/encoding/unicode"
)

type LDAP struct {
	Conn   *ldap.Conn
	Logger *zap.Logger
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

	userDN := fmt.Sprintf("CN=%s,CN=Users,DC=aku,DC=ac,DC=ir", username)

	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)

	passReq := ldap.NewModifyRequest(userDN, nil)

	pwdEncoded, _ := utf16.NewEncoder().String(fmt.Sprintf("\"%s\"", password))
	passReq.Replace("unicodePwd", []string{pwdEncoded})

	if err := l.Conn.Modify(passReq); err != nil {
		if ldap.IsErrorWithCode(err, 32) {
			l.Logger.Error("user does not exist", zap.String("username", username))

			return echo.ErrNotFound
		}

		log.Fatal(err)

		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, username)
}

func (l LDAP) Register(g *echo.Group) {
	g.GET("/change-password", l.ChangePassword)
}
