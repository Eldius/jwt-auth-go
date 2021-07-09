package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

func SetDefaults() {
	//viper.SetDefault("auth.database.url", "test.db")
	//viper.SetDefault("auth.database.engine", "sqlite3")
	viper.SetDefault("auth.user.pattern", "^[a-zA-Z0-9\\._-]*$")
	viper.SetDefault("auth.pass.pattern", "^[a-zA-Z0-9\\._-]*$")
	viper.SetDefault("auth.jwt.secret", uuid.New().String())
	viper.SetDefault("auth.user.default.active", true)
	viper.SetDefault("auth.jwt.ttl", "0s")
}

func SetupViper(cfgFile string) {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		viper.AddConfigPath(filepath.Join(home, ".auth-server"))
		viper.SetConfigName("auth-server")
		viper.SetConfigType("yml")
	}
	SetDefaults()
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
