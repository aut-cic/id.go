package config

// Default return default configuration.
func Default() Config {
	return Config{
		Address:  "127.0.0.1",
		Username: "admin",
		Password: "pass",
	}
}
