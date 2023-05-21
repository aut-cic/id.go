package main

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/aut-cic/id.go/internal/config"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/text/encoding/unicode"
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

	username := "kahr123"

	userDN := fmt.Sprintf("CN=%s,CN=Users,DC=aku,DC=ac,DC=ir", username)

	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	// According to the MS docs in the links above
	// The password needs to be enclosed in quotes
	pwdEncoded, _ := utf16.NewEncoder().String("\"Test@123\"")
	passReq := ldap.NewModifyRequest(userDN, nil)

	passReq.Replace("unicodePwd", []string{pwdEncoded})

	if err := l.Modify(passReq); err != nil {
		if ldap.IsErrorWithCode(err, 32) {
			log.Fatalf("user %s does not exist", username)
		}
		log.Fatal(err)
	}
}
