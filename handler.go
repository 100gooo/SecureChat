package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
)

type Message struct {
    Text string `json:"text"`
}

var aesKey []byte

func init() {
    key := os.Getenv("AES_KEY")
    if len(key) != 32 {
        log.Panicf("AES_KEY must be 32 bytes long, got %d bytes", len(key))
    }
    aesKey = []byte(key)
}

func encrypt(text string) (string, error) {
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return "", fmt.Errorf("error creating AES cipher: %v", err)
    }

    b := base64.StdEncoding.EncodeToString([]byte(text))
    ciphertext := make([]byte, aes.BlockSize+len(b))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", fmt.Errorf("error generating IV: %v", err)
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))

    return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decrypt(encodedText string) (string, error) {
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return "", fmt.Errorf("error creating AES cipher: %v", err)
    }

    decodedMsg, err := base64.URLEncoding.DecodeString(encodedText)
    if err != nil {
        return "", fmt.Errorf("error decoding message: %v", err)
    }

    if len(decodedMsg) < aes.BlockSize {
        return "", fmt.Errorf("ciphertext too short")
    }
    iv := decodedMsg[:aes.BlockSize]
    decodedMsg = decodedMsg[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(decodedMsg, decodedMsg)

    decodedText, err := base64.StdEncoding.DecodeString(string(decodedMsg))
    if err != nil {
        return "", fmt.Errorf("error decoding base64 text: %v", err)
    }

    return string(decodedText), nil
}

func handleSendMessage(w http.ResponseWriter, r *http.Request) {
    var msg Message
    if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
        http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
        return
    }
    encryptedText, err := encrypt(msg.Text)
    if err != nil {
        http.Error(w, fmt.Sprintf("Error encrypting message: %v", err), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte(encryptedText))
}

func handleRetrieveMessage(w http.ResponseWriter, r *http.Request) {
    encryptedText := r.URL.Query().Get("encryptedText")
    if encryptedText == "" {
        http.Error(w, "Missing encryptedText parameter", http.StatusBadRequest)
        return
    }
    decryptedText, err := decrypt(encryptedText)
    if err != nil {
        http.Error(w, fmt.Sprintf("Error decrypting message: %v", err), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte("Text: " + decryptedText))
}

func main() {
    http.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "POST" {
            handleSendMessage(w, r)
        } else {
            http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        }
    })

    http.HandleFunc("/retrieve", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "GET" {
            handleRetrieveMessage(w, r)
        } else {
            http.Error(w, "Invalid request Type", http.StatusMethodNotAllowed)
        }
    })

    log.Fatal(http.ListenAndServe(":8080", nil))
}