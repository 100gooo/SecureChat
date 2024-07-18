package logger

import (
	"log"
	"os"
	"github.com/joho/godotenv"
)

var Logger *log.Logger

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	logFile := os.Getenv("LOG_FILE")
	var output *os.File
	if logFile != "" {
		output, err = os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file %s: %v", logFile, err)
		}
	} else {
		output = os.Stdout
	}

	Logger = log.New(output, "SecureChat: ", log.LstdFlags|log.Lshortfile)
}