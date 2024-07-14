package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Configuration struct {
	ServerPort  string
	DatabaseURL string
	JWTSecret   string
}

func LoadEnv() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}
}

func GetProficientConfig() *Configuration {
	LoadEnv()

	conf := &Configuration{
		ServerPort:  os.Getenv("SERVER_PORT"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
	}

	return conf
}