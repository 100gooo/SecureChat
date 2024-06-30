package main

import (
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"yourproject/handler"
)

var once sync.Once

func setupHandlers() {
	once.Do(func() {
		http.HandleFunc("/status", handler.StatusItHandler)
	})
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	httpPort := os.Getenv("PORT")
	if httpPort == "" {
		log.Fatal("Environment variable $PORT must be set")
	}

	setupHandlers()

	server := &http.Server{
		Addr:         ":" + httpPort,
		Handler:      nil,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Starting server on port %s", httpPort)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server on port %s: %v", httpPort, err)
	}
}