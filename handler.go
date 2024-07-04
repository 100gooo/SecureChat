package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
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
        log.Fatal("AES_KEY must be 32 bytes long")
    }
    aesKey = []byte(key)
}

func encrypt(text string) (string, error) {
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return "", err
    }

    b := base64.StdEncoding.EncodeToString([]byte(text))
    ciphertext := make([]byte, aes.BlockSize+len(b))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))

    return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decrypt(encodedText string) (string, error) {
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return "", err
    }

    decodedMsg, err := base64.URLEncoding.DecodeString(encodedText)
    if err != nil {
        return "", err
    }

    if len(decodedMsg) < aes.BlockSize {
        return "", err
    }
    iv := decodedMsg[:aes.BlockSize]
    decodedMsg = decodedMsg[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(decodedMsg, decodedMsg)

    decodedText, err := base64.StdEncoding.DecodeString(string(decodedMsg))
    if err != nil {
        return "", err
    }

    return string(decodedText), nil
}

func handleSendMessage(w http.ResponseWriter, r *http.Request) {
    var msg Message
    if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }
    encryptedText, err := encrypt(msg.Text)
    if err != nil {
        http.Error(w, "Error encrypting message", http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(encryptedText))
}

func handleRetrieveMessage(w http.ResponseWriter, r *http.Request) {
    encryptedText := r.URL.Query().Get("encryptedText")
    if encryptedTitle == "" {
        http.Error(w, "Missing encryptedText parameter", http.StatusBadRequest)
        return
    }
    decryptedText, err := decrypt(encryptedText)
    if err != nil {
        http.Error(w, "Error decrypting message", http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Text: " + decryptedTitle))
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
            http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        }
    })

    log.Fatal(http.ListenAndServe(":8080", nil))
}