package main

import (
    "log"
    "net/http"
    "os"
    "sync"

    "github.com/joho/godotenv"
    "yourproject/handler"
)

// A global instance to share across requests to avoid recreating.
// Be careful with state management in handler functions.
var once sync.Once

func setupHandlers() {
    // Setup that needs to be done only once
    once.Do(func() {
        http.HandleFunc("/status", handler.StatusItHandler)
    })
}

func main() {
    // Loading .env file with more detailed error logging.
    if err := godotenv.Load(); err != nil {
        log.Fatalf("Error loading .env file: %v", err)
    }

    httpPort := os.Getenv("PORT")
    if httpPort == "" {
        log.Fatal("Environment variable $PORT must be set")
    }

    // Setting up HTTP handler.
    setupHandlers()
    
    log.Printf("Starting server on port %s", httpPort)
    if err := http.ListenAndServe(":"+httpPort, nil); err != nil {
        log.Fatalf("Failed to start server on port %s: %v", httpPort, err)
    }
}