package main

import (
    "log"
    "net/http"
    "os"

    "github.com/joho/godotenv"
    "yourproject/handler"
)

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
    http.HandleFunc("/status", handler.StatusItHandler)

    log.Printf("Starting server on port %s", httpPort)
    if err := http.ListenAndServe(":"+httpPort, nil); err != nil {
        log.Fatalf("Failed to start server on port %s: %v", httpPort, err)
    }
}