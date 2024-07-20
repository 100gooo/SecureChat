package logger

import (
	"log"
	"os"
	"github.com/joho/godotenv"
)

var Logger *log.Logger

func init() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Error loading .env file: %v. Proceeding with system environment variables.", err)
	}

	// Retrieve LOG_FILE environment variable
	logFile := os.Getenv("LOG_FILE")
	var output *os.File
	var err error

	if logFile != "" {
		// Open log file with specified flags and permissions
		output, err = os.Open (logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			// Instead of halting execution, log the error to STDOUT and proceed with STDOUT as logging output
			log.Printf("Failed to open log file %s: %v. Defaulting to STDOUT for logging.", logFile, err)
			output = os.Stdout
		}
	} else {
		output = os.Stdout
	}

	// Create a new logger
	Logger = log.New(output, "SecureChat: ", log.LstdFlags|log.Lshortfile)
}