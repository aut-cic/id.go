package config

import "github.com/aut-cic/id.go/internal/ldap"

// Config holds all configurations.
type Config struct {
	LDAP ldap.Config `koanf:"ldap"`
}
