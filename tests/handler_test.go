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

func handler(w http.ResponseWriter, r *http.Request) {
	key := []byte(os.Getenv("ENCRYPTION_KEY"))
	switch r.URL.Path {
	case "/encrypt":
		msg := r.URL.Query().Get("msg")
		if encrypted, err := encrypt(key, msg); err == nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(encrypted))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	case "/decrypt":
		encMsg := r.URL.Query().Get("msg")
		if decrypted, err := decrypt(key, encMsg); err == nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(decrypted))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func encrypt(key []byte, message string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	b := base64.StdEncoding.EncodeToString([]byte(message))
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decrypt(key []byte, encryptedMessage string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	encryptedBytes, err := base64.URLEncoding.DecodeString(encryptedMessage)
	if err != nil {
		return "", err
	}
	if len(encryptedBytes) < aes.BlockSize {
		return "", err
	}
	iv := encryptedBytes[:aes.BlockSize]
	encryptedBytes = encryptedBytes[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encryptedBytes, encryptedBytes)

	data, err := base64.StdEncoding.DecodeString(string(encryptedBytes))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func TestEncryptDecrypt(t *testing.T) {
	os.Setenv("ENCRYPTION_KEY", "thisIsASecretKey12345")
	handlerFunc := http.HandlerFunc(handler)

	t.Run("testEncryptionDecryption", func(t *testing.T) {
		msg := "hello, world"
		req, err := http.NewRequest("GET", "/encrypt?msg="+msg, nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		handlerFunc.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		encryptedMsg := rr.Body.String()

		req2, err := http.NewRequest("GET", "/decrypt?msg="+encryptedMsg, nil)
		if err != nil {
			t.Fatal(err)
		}

		rr2 := httptest.NewRecorder()
		handlerFunc.ServeHTTP(rr2, req2)

		if status := rr2.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		decryptedMsg := rr2.Body.String()
		if decryptedMsg != msg {
			t.Errorf("decryption failed: got %v want %v", decryptedMsg, msg)
		}
	})
}

func TestHandlerResponse(t *testing.T) {
	os.Setenv("ENCRYPTION_KEY", "thisIsASecretKey12345")
	handlerFunc := http.HandlerFunc(handler)

	t.Run("testValidRequest", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/encrypt?msg=test", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		handlerFunc.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code for valid request: got %v want %v", status, http.StatusOK)
		}
	})

	t.Run("testInvalidRequest", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/nonexistent", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		handlerFunc.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusNotFound {
			t.Errorf("handler returned wrong status code for invalid request: got %v want %v", status, http.StatusNotFound)
		}
	})
}