package main

import (
    "os"
    "testing"
    "log"

    "github.com/stretchr/testify/assert"
    "github.com/yourproject/securechat/encryption"
)

func init() {
    os.Setenv("ENCRYPTION_KEY", "your-32-length-secure-encryption-key")
    // Initialize log format
    log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func logMessage(message string) {
    log.Println("SecureChat Log:", message)
}

func TestEncryptDecryptCycle(t *testing.T) {
    testMessages := []string{
        "Hello, World!",
        "Another test message with a bit more length to it.",
        "",
        "1234567890",
    }

    for _, testMessage := range testMessages {
        logMessage("Starting encryption/decryption cycle for: " + testMessage)
        encryptedMsg, encryptErr := encryption.Encrypt(testMessage)
        if encryptErr != nil {
            t.Fatalf("Encryption failed: %v", encryptErr)
        }

        logMessage("Encryption succeeded. Encrypted message: " + encryptedMsg)

        decryptedMsg, decryptErr := encryption.Decrypt(encryptedMsg)
        if decryptErr != nil {
            t.Fatalf("Decryption failed: %v", decryptErr)
        }

        logMessage("Decryption succeeded. Decrypted message: " + decryptedMsg)
        
        assert.Equal(t, testMessage, decryptedMsg, "Decrypted message differs from the original")
    }
}

func TestEncryptionUniqueness(t *testing.T) {
    testMessage := "This is a uniqueness test."
    logMessage("Testing encryption uniqueness for: " + testMessage)

    firstEncryptionResult, firstErr := encryption.Encrypt(testMessage)
    if firstErr != nil {
        t.Fatalf("Encryption failed on first attempt: %v", firstErr)
    }
    logMessage("First encryption result: " + firstEncryptionResult)

    secondEncryptionResult, secondErr := encryption.Encrypt(testMessage)
    if secondErr != nil {
        t.Fatalf("Encryption failed on second attempt: %v", secondErr)
    }
    logMessage("Second encryption result: " + secondEncryptionResult)

    assert.NotEqual(t, firstEncryptionResult, secondEncryptionResult, "Repeated encryption results should not match")
}

func TestInvalidInputs(t *testing.T) {
    logMessage("Testing encryption and decryption on invalid inputs")

    _, errOnEmptyEncrypt := encryption.Encrypt("")
    assert.Error(t, errOnEmptyEncrypt, "Expected error when encrypting empty string")

    _, errOnEmptyDecrypt := encryption.Decrypt("")
    assert.Error(t, errOnEmptyDecrypt, "Expected error when decrypting empty string")
}