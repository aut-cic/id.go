package main

import (
	"log"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/text/encoding/unicode"
)

func main() {
	l, err := ldap.DialURL("ldap://<address>")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	if err := l.Bind("CN=<username>,CN=Users,DC=aku,DC=ac,DC=ir", "<password>"); err != nil {
		log.Fatal(err)
	}

	userDN := "CN=parham.alvani,CN=Users,DC=aku,DC=ac,DC=ir"

	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	// According to the MS docs in the links above
	// The password needs to be enclosed in quotes
	pwdEncoded, _ := utf16.NewEncoder().String("12345")
	passReq := ldap.NewModifyRequest(userDN, nil)

	passReq.Add("unicodePwd", []string{pwdEncoded})

	if err := l.Modify(passReq); err != nil {
	}
}
