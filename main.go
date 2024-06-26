package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"yourproject/handler"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	httpPort := os.Getenv("PORT")
	if httpPort == "" {
		log.Fatal("$PORT must be set")
	}

	http.HandleFunc("/status", handler.StatusHandler)

	log.Println("Starting server on port " + httpPort)
	if err := http.ListenAndServe(":"+httpPort, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}