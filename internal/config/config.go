package config

// Config holds all configurations.
type Config struct {
	Address  string `koanf:"address"`
	Username string `koanf:"username"`
	Password string `koanf:"password"`
}
