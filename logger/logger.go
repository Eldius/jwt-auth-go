package logger

import (
	"os"

	"github.com/eldius/jwt-auth-go/config"
	"github.com/sirupsen/logrus"
)

var appLogger *logrus.Entry

func setup() {
	if appLogger == nil {
		hostname, _ := os.Hostname()
		var standardFields = logrus.Fields{
			"hostname": hostname,
		}

		logrus.SetFormatter(&logrus.JSONFormatter{})
		logrus.SetReportCaller(true)
		format := config.GetLoggerFormat()
		if format == "text" {
			logrus.SetFormatter(&logrus.TextFormatter{})
		} else {
			logrus.SetFormatter(&logrus.JSONFormatter{})
		}
		appLogger = logrus.WithFields(standardFields)
	}
}

/*
Debug debug logs
*/
func Debug(args ...interface{}) {
	Logger().Debug(args...)
}

/*
DebugWithParams debug logs
*/
func DebugWithParams(params map[string]interface{}, args ...interface{}) {
	Logger().
		WithFields(params).
		Debug(args...)
}

/*
Error error logs
*/
func Error(args ...interface{}) {
	Logger().Error(args...)

}

/*
ErrorWithParams debug logs
*/
func ErrorWithParams(params map[string]interface{}, args ...interface{}) {
	Logger().
		WithFields(params).
		Error(args...)
}

/*
Logger returns the app logger
*/
func Logger() *logrus.Entry {
	setup()
	return appLogger
}
