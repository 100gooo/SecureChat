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

func encryptionHandler(w http.ResponseWriter, r *http.Request) {
	encryptionKey := []byte(os.Getenv("ENCRYPTION_KEY"))
	switch r.URL.Path {
	case "/encrypt":
		plainMessage := r.URL.Query().Get("msg")
		if encryptedMessage, err := encryptMessage(encryptionKey, plainMessage); err == nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(encryptedMessage))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	case "/decrypt":
		encryptedQueryMessage := r.URL.Query().Get("msg")
		if decryptedMessage, err := decryptMessage(encryptionKey, encryptedQueryMessage); err == nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(decryptedMessage))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func encryptMessage(key []byte, plainText string) (string, error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	base64EncodedPlainText := base64.StdEncoding.EncodeToString([]byte(plainText))
	cipherText := make([]byte, aes.BlockSize+len(base64EncodedPlainText))
	initializationVector := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, initializationVector); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(cipherBlock, initializationVector)
	stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(base64EncodedPlainText))
	return base64.URLEncoding.EncodeToString(cipherText), nil
}

func decryptMessage(key []byte, encryptedBase64Text string) (string, error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	encryptedBytes, err := base64.URLEncoding.DecodeString(encryptedBase64Text)
	if err != nil {
		return "", err
	}
	if len(encryptedBytes) < aes.BlockSize {
		return "", err
	}
	initializationVector := encryptedBytes[:aes.BlockSize]
	encryptedBytes = encryptedBytes[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(cipherBlock, initializationVector)
	stream.XORKeyStream(encryptedBytes, encryptedBytes)

	decryptedData, err := base64.StdEncoding.DecodeString(string(encryptedBytes))
	if err != nil {
		return "", err
	}
	return string(decryptedData), nil
}

func TestEncryptDecryptFlow(t *testing.T) {
	os.Setenv("ENCRYPTION_KEY", "thisIsASecretKey12345")
	httpHandlerFunc := http.HandlerFunc(encryptionHandler)

	t.Run("testEncryptionDecryption", func(t *testing.T) {
		message := "hello, world"
		request, err := http.NewRequest("GET", "/encrypt?msg="+message, nil)
		if err != nil {
			t.Fatal(err)
		}

		encryptionRecorder := httptest.NewRecorder()
		httpHandlerFunc.ServeHTTP(encryptionRecorder, request)

		if status := encryptionRecorder.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		encryptedMessage := encryptionRecorder.Body.String()

		decryptionRequest, err := http.NewRequest("GET", "/decrypt?msg="+encryptedMessage, nil)
		if err != nil {
			t.Fatal(err)
		}

		decryptionRecorder := httptest.NewRecorder()
		httpHandlerFunc.ServeHTTP(decryptionRecorder, decryptionRequest)

		if status := decryptionRecorder.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		decryptedMessage := decryptionRecorder.Body.String()
		if decryptedMessage != message {
			t.Errorf("decryption failed: got %v want %v", decryptedMessage, message)
		}
	})
}

func TestHTTPHandlerResponses(t *testing.T) {
	os.Setenv("ENCRYPTION_KEY", "thisIsASecretKey12345")
	httpHandlerFunc := http.HandlerFunc(encryptionHandler)

	t.Run("testValidRequest", func(t *testing.T) {
		encryptionRequest, err := http.NewRequest("GET", "/encrypt?msg=test", nil)
		if err != nil {
			t.Fatal(err)
		}

		recorder := httptest.NewRecorder()
		httpHandlerFunc.ServeHTTP(recorder, encryptionRequest)

		if status := recorder.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code for valid request: got %v want %v", status, http.StatusOK)
		}
	})

	t.Run("testInvalidRequest", func(t *testing.T) {
		invalidRequest, err := http.NewRequest("GET", "/nonexistent", nil)
		if err != nil {
			t.Fatal(err)
		}

		recorder := httptest.NewRecorder()
		httpHandlerFunc.ServeHTTP(recorder, invalidRequest)

		if status := recorder.Code; status != http.StatusNotFound {
			t.Errorf("handler returned wrong status code for invalid request: got %v want %v", status, http.StatusNotFound)
		}
	})
}