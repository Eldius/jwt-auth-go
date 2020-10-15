package config

import "github.com/spf13/viper"

// GetDBURL returns the database url
func GetDBURL() string {
	return viper.GetString("auth.database.url")
}

// GetDBEngine returns the database engine name
func GetDBEngine() string {
	return viper.GetString("auth.database.engine")
}

// GetDBLogQueries enable query log info
func GetDBLogQueries() bool {
	return viper.GetBool("auth.database.log")
}

/*
GetUsernamePattern returns the pattern to
validate username
*/
func GetUsernamePattern() string {
	return viper.GetString("auth.user.pattern")
}

/*
GetJWTSecret returns the JWT secret to be used
*/
func GetJWTSecret() string {
	return viper.GetString("auth.jwt.secret")
}
