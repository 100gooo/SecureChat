package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func secureMessageHandler(w http.ResponseWriter, r *http.Request) {
	secretKey := []byte(os.Getenv("ENCRYPTION_KEY"))
	switch r.URL.Path {
	case "/encrypt":
		messageToEncrypt := r.URL.Query().Get("msg")
		if encryptedText, err := encryptText(secretKey, messageToEncrypt); err == nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(encryptedText))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	case "/decrypt":
		encryptedMessage := r.URL.Query().Get("msg")
		if decryptedText, err := decryptText(secretKey, encryptedMessage); err == nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(decryptedText))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func encryptText(key []byte, plaintext string) (string, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	rawText := base64.StdEncoding.EncodeToString([]byte(plaintext))
	encryptedBuffer := make([]byte, aes.BlockSize+len(rawText))
	iv := encryptedBuffer[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	encrypter := cipher.NewCFBEncrypter(blockCipher, iv)
	encrypter.XORKeyStream(encryptedBuffer[aes.BlockSize:], []byte(rawText))
	return base64.URLEncoding.EncodeToString(encryptedBuffer), nil
}

func decryptText(key []byte, encryptedText string) (string, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	encryptedBytes, err := base64.URLEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}
	if len(encryptedBytes) < aes.BlockSize {
		return "", err
	}
	iv := encryptedBytes[:aes.BlockSize]
	encryptedContent := encryptedBytes[aes.BlockSize:]

	decrypter := cipher.NewCFBDecrypter(blockCipher, iv)
	decrypter.XORKeyStream(encryptedContent, encryptedContent)

	decryptedData, err := base64.StdEncoding.DecodeString(string(encryptedContent))
	if err != nil {
		return "", err
	}
	return string(decryptedData), nil
}

func TestSecureMessageHandlerFlow(t *testing.T) {
	os.Setenv("ENCRYPTION_KEY", "thisIsASecretKey12345")
	handlerFunc := http.HandlerFunc(secureMessageHandler)

	t.Run("testEncryptionDecryption", func(t *testing.T) {
		testMessage := "hello, world"
		encryptRequest, err := http.NewRequest("GET", "/encrypt?msg="+testMessage, nil)
		if err != nil {
			t.Fatal(err)
		}

		encryptRecorder := httptest.NewRecorder()
		handlerFunc.ServeHTTP(encryptRecorder, encryptRequest)

		if status := encryptRecorder.Code; status != http.StatusOK {
			t.Errorf("Encryption handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		encryptedMsg := encryptRecorder.Body.String()

		decryptRequest, err := http.NewRequest("GET", "/decrypt?msg="+encryptedMsg, nil)
		if err != nil {
			t.Fatal(err)
		}

		decryptRecorder := httptest.NewRecorder()
		handlerFunc.ServeHTTP(decryptRecorder, decryptRequest)

		if status := decryptRecorder.Code; status != http.StatusOK {
			t.Errorf("Decryption handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		decryptedMsg := decryptRecorder.Body.String()
		if decryptedMsg != testMessage {
			t.Errorf("Decryption failed: got %v want %v", decryptedMsg, testMessage)
		}
	})
}

func TestSecureMessageHandlerResponses(t *testing.T) {
	os.Setenv("ENCRYPTION_KEY", "thisIsASecretKey12345")
	handlerFunc := http.HandlerFunc(secureMessageHandler)

	t.Run("testValidRequest", func(t *testing.T) {
		encryptRequest, err := http.NewRequest("GET", "/encrypt?msg=test", nil)
		if err != nil {
			t.Fatal(err)
		}

		recorder := httptest.NewRecorder()
		handlerFunc.ServeHTTP(recorder, encryptRequest)

		if status := recorder.Code; status != http.StatusOK {
			t.Errorf("Valid request handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}
	})

	t.Run("testInvalidRequest", func(t *testing.T) {
		invalidRequest, err := http.NewRequest("GET", "/nonexistent", nil)
		if err != nil {
			t.Fatal(err)
		}

		recorder := httptest.NewRecorder()
		handlerFunc.ServeHTTP(recorder, invalidRequest)

		if status := recorder.Code; status != http.StatusNotFound {
			t.Errorf("Invalid request handler returned wrong status code: got %v want %v", status, http.StatusNotFound)
		}
	})
}