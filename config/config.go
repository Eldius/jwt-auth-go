package config

import (
	"time"

	"github.com/spf13/viper"
)

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
GetPasswordPattern returns the pattern to
validate password
*/
func GetPasswordPattern() string {
	return viper.GetString("auth.pass.pattern")
}

/*
GetJWTSecret returns the JWT secret to be used
*/
func GetJWTSecret() string {
	return viper.GetString("auth.jwt.secret")
}

/*
GetUserDefaultActive returns configuration about
new users will be created active or inactive
*/
func GetUserDefaultActive() bool {
	return viper.GetBool("auth.user.default.active")
}

/*
GetDefaultJwtTTL returns the JWT TTL (the time
util JWT will expire)
*/
func GetDefaultJwtTTL() time.Duration {
	return viper.GetDuration("auth.jwt.ttl")
}

/*
GetLoggerFormat returns the type of log
*/
func GetLoggerFormat() string {
	return viper.GetString("app.log.format")
}
