package utility

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

func LoadEncryptionKey() ([]byte, error) {
	key := os.Getenv("ENCRYPTION_KEY")
	if key == "" {
		return nil, fmt.Errorf("ENCRYPTION_KEY is not set in environment variables")
	}
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode ENCRYPTION_KEY: %v", err)
	}
	return decodedDiscreteByteKey, nil
}

func Encrypt(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("could not create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("could not generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(ciphertext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("could not create GCM: %v", err)
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %v", err)
	}

	if len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("malformed ciphertext")
	}

	nonce, ciphertextData := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gmc.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("could not decrypt data: %v", err)
	}

	return string(plaintext), nil
}