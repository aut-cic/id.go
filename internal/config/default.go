package config

import "github.com/aut-cic/id.go/internal/ldap"

// Default return default configuration.
func Default() Config {
	return Config{
		LDAP: ldap.Config{
			Address:  "127.0.0.1",
			Username: "admin",
			Password: "pass",
		},
	}
}
