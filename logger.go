package logger

import (
	"log"
	"os"
	"github.com/joho/godotenv"
)

var ApplicationLogger *log.Logger

func init() {
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Failed to load .env file: %v. Using system environment variables instead.", err)
	}

	logFilePath := os.Getenv("LOG_FILE")
	var logOutputDestination *os.File
	var fileError error

	if logFilePath != "" {
		logOutputDestination, fileError = os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if fileError != nil {
			log.Printf("Error: Could not open log file %s: %v. Falling back to STDOUT for logging output.", logFilePath, fileError)
			logOutputDestination = os.Stdout
		}
	} else {
		logOutputDestination = os.Stdout
	}

	ApplicationLogger = log.New(logOutputDestination, "SecureChat: ", log.LstdFlags|log.Lshortput)
}