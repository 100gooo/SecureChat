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

func TestEncryptDecryptCycle(t *testing.T) {
    testMessages := []string{
        "Hello, World!",
        "Another test message with a bit more length to it.",
        "",
        "1234567890",
    }

    for _, testMessage := range testMessages {
        encryptedMsg, encryptErr := encryption.Encrypt(testMessage)
        if encryptErr != nil {
            t.Fatalf("Encryption failed: %v", encryptErr)
        }

        decryptedMsg, decryptErr := encryption.Decrypt(encryptedMsg)
        if decryptErr != nil {
            t.Fatalf("Decryption failed: %v", decryptErr)
        }

        assert.Equal(t, testMessage, decryptedMsg, "Decrypted message differs from the original")
    }
}

func TestEncryptionUniqueness(t *testing.T) {
    testMessage := "This is a uniqueness test."

    firstEncryptionResult, firstErr := encryption.Encrypt(testMessage)
    if firstErr != nil {
        t.Fatalf("Encryption failed on first attempt: %v", firstErr)
    }

    secondEncryptionResult, secondErr := encryption.Encrypt(testMessage)
    if secondErr != nil {
        t.Fatalf("Encryption failed on second attempt: %v", secondErr)
    }

    assert.NotEqual(t, firstEncryptionResult, secondEncryptionResult, "Repeated encryption results should not match")
}

func TestInvalidInputs(t *testing.T) {
    _, errOnEmptyEncrypt := encryption.Encrypt("")
    assert.Error(t, errOnEmptyEncrypt, "Expected error when encrypting empty string")

    _, errOnEmptyDecrypt := encryption.Decrypt("")
    assert.Error(t, errOnEmptyDecrypt, "Expected error when decrypting empty string")
}