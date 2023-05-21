package ldap

type Config struct {
	Username string `koanf:"username"`
	Password string `koanf:"password"`
	Address  string `koanf:"address"`
}
