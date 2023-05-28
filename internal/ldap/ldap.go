package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"regexp"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
	"golang.org/x/text/encoding/unicode"
)

const (
	controlTypeLdapServerPolicyHints           = "1.2.840.113556.1.4.2239"
	controlTypeLdapServerPolicyHintsDeprecated = "1.2.840.113556.1.4.2066"
)

var (
	ErrUserNotFound         = errors.New("user does not exist")
	ErrPasswordPolicyFailed = errors.New("password does not match the policy on server (password history, complexity)")
	ldapErrorMatchRegex     = regexp.MustCompile(`: ([A-F0-9]+): SvcErr: ([\w-]+)`)
)

type Manager struct {
	Config
	Logger *zap.Logger
}

func New(cfg Config, logger *zap.Logger) (Manager, error) {
	m := Manager{
		Config: cfg,
		Logger: logger,
	}

	conn, err := m.connect()
	if err != nil {
		return m, err
	}
	defer conn.Close()

	who, err := conn.WhoAmI(nil)
	if err != nil {
		return m, fmt.Errorf("ldap whoami failed: %w", err)
	}

	logger.Info("ldap knows us", zap.String("AuthzID", who.AuthzID))

	return m, nil
}

func (m Manager) connect() (*ldap.Conn, error) {
	// nolint: gosec, exhaustruct
	l, err := ldap.DialTLS("tcp", m.Address, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, fmt.Errorf("ldap connection failed: %w", err)
	}

	if err := l.Bind(fmt.Sprintf("CN=%s,CN=Users,DC=aku,DC=ac,DC=ir", m.Username), m.Password); err != nil {
		return nil, fmt.Errorf("ldap bind failed: %w", err)
	}

	return l, nil
}

// nolint: funlen, cyclop
func (m Manager) ChangePassword(username string, password string) error {
	// PasswordModify does not work with AD
	// https://github.com/go-ldap/ldap/issues/106
	conn, err := m.connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	userDN := fmt.Sprintf("CN=%s,CN=Users,DC=aku,DC=ac,DC=ir", username)

	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)

	pwdEncoded, err := utf16.NewEncoder().String(fmt.Sprintf("\"%s\"", password))
	if err != nil {
		return fmt.Errorf("cannot encode password using utf16: %w", err)
	}

	m.Logger.Info("password encoded to utf16",
		zap.String("username", username),
		zap.String("encoded-password", pwdEncoded),
	)

	passReq := ldap.NewModifyRequest(userDN, nil)

	passReq.Replace("unicodePwd", []string{pwdEncoded})

	// nolint: gomnd
	if err := conn.Modify(passReq); err != nil {
		if ldap.IsErrorWithCode(err, 32) {
			return ErrUserNotFound
		}

		// catch some common ldap error messages and make them human readable
		if ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform) {
			errCodes := ldapErrorMatchRegex.FindStringSubmatch(err.Error())
			if errCodes != nil {
				switch errCodes[1] {
				case "0000052D":
					return ErrPasswordPolicyFailed
				default:
				}
			}
		}

		return fmt.Errorf("ldap modify request failed: %w", err)
	}

	m.Logger.Info("password modify was successful", zap.String("username", username), zap.String("password", password))

	return nil
}
