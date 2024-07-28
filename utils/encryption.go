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

// LoadEncryptionKey loads the encryption key from the environment variable, decodes it from base64, and returns the key bytes.
func LoadEncryptionKey() ([]byte, error) {
    // Retrieve the base64-encoded key string from the environment
    encodedKey := os.Getenv("ENCRYPTION_KEY")
    if encodedKey == "" {
        return nil, fmt.Errorf("ENCRYPTION_KEY is not set in environment variables")
    }

    // Decode the base64-encoded encryption key
    decodedKey, err := base64.StdEncoding.DecodeString(encodedKey)
    if err != nil {
        return nil, fmt.Errorf("failed to decode ENCRYPTION_KEY: %v", err)
    }

    return decodedKey, nil
}

// Encrypt takes plaintext and a key, encrypts the data, and returns the ciphertext encoded in base64.
func Encrypt(plaintext string, key []byte) (string, error) {
    // Create a new AES cipher using the key
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", fmt.Errorf("could not create cipher: %v", err)
    }

    // Create a Galois Counter Mode (GCM) cipher from the AES cipher
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", fmt.Errorf("could not create GCM: %v", err)
    }

    // Generate a unique nonce for this encryption
    nonce := make([]byte, gcm.NonceSize())
    _, err = io.ReadFull(rand.Reader, nonce)
    if err != nil {
        return "", fmt.Errorf("could not generate nonce: %v", err)
    }

    // Encrypt the plaintext, prefixing it with the nonce
    ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt takes a base64-encoded ciphertext and a key, decrypts the data, and returns the plaintext.
func Decrypt(ciphertext string, key []byte) (string, error) {
    // Create a new AES cipher using the key
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", fmt.Errorf("could not create cipher: %v", err)
    }

    // Create a Galois Counter Mode (GCM) cipher from the AES cipher
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", fmt.Errorf("could not create GCM: %v", err)
    }

    // Decode the base64-encoded ciphertext
    data, err := base64.StdEncoding.DecodeString(ciphertext)
    if err != nil {
        return "", fmt.Errorf("failed to decode ciphertext: %v", err)
    }

    // Split the nonce away from the ciphertext
    if len(data) < gcm.NonceSize() {
        return "", fmt.Errorf("malformed ciphertext")
    }
    nonce, ciphertextData := data[:gcm.NonceSize()], data[gcm.NonceSize():]

    // Decrypt the data
    plaintext, err := gcm.Open(nil, nonce, ciphertextData, nil)
    if err != nil {
        return "", fmt.Errorf("could not decrypt data: %v", err)
    }

    return string(plaintext), nil
}