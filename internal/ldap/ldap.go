package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/text/encoding/unicode"
)

var ErrUserNotFound = errors.New("user does not exist")

type Manager struct {
	Username string
	Password string
	Address  string
}

func (m Manager) connect() (*ldap.Conn, error) {
	l, err := ldap.DialURL(fmt.Sprintf("ldap://%s", m.Address))
	if err != nil {
		return nil, err
	}
	defer l.Close()

	if err := l.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		return nil, err
	}

	if err := l.Bind(fmt.Sprintf("CN=%s,CN=Users,DC=aku,DC=ac,DC=ir", m.Username), m.Password); err != nil {
		return nil, err
	}

	return l, nil
}

func (m Manager) ChangePassword(username string, password string) error {
	conn, err := m.connect()
	if err != nil {
		return err
	}

	userDN := fmt.Sprintf("CN=%s,CN=Users,DC=aku,DC=ac,DC=ir", username)

	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)

	passReq := ldap.NewModifyRequest(userDN, nil)

	pwdEncoded, _ := utf16.NewEncoder().String(fmt.Sprintf("\"%s\"", password))
	passReq.Replace("unicodePwd", []string{pwdEncoded})

	if err := conn.Modify(passReq); err != nil {
		if ldap.IsErrorWithCode(err, 32) {
			return ErrUserNotFound
		}

		return err
	}

	return nil
}
