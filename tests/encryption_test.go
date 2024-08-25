package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yourproject/securechat/encryption"
)

func init() {
	os.Setenv("ENCRYPTION_KEY", "your-32-length-secure-encryption-key")
}

func TestEncryptDecrypt(t *testing.T) {
	messages := []string{
		"Hello, World!",
		"Another test message with a bit more length to it.",
		"",
		"1234567890",
	}

	for _, originalMessage := range messages {
		encryptedMessage, err := encryption.Encrypt(originalMessage)
		if err != nil {
			t.Fatalf("Failed to encrypt message: %v", err)
		}

		decryptedMessage, err := encryption.Decrypt(encryptedMessage)
		if err != nil {
			t.Fatalf("Failed to decrypt message: %v", err)
		}

		assert.Equal(t, originalMessage, decryptedMessage, "The decrypted message does not match the original")
	}
}

func TestEncryptionSecurity(t *testing.T) {
	message := "This is a security test."

	encryptionResult1, err := encryption.Encrypt(message)
	if err != nil {
		t.Fatalf("Failed to encrypt message: %v", err)
	}

	encryptionResult2, err := encryption.Encrypt(message)
	if err != nil {
		t.Fatalf("Failed to encrypt message: %v", err)
	}

	assert.NotEqual(t, encryptionResult1, encryptionResult2, "Two encryption outputs for the same input are identical. IV might be static.")
}

func TestErrorHandling(t *testing.T) {
	_, encryptErr := encryption.Encrypt("")
	assert.Error(t, encryptErr, "Encryption should fail on empty input")

	_, decryptErr := encryption.Decrypt("")
	assert.Error(t, decryptErr, "Decryption should fail on empty input")
}