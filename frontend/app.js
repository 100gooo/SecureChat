import io from 'socket.io-client';
import CryptoJS from 'crypto-js';

const SERVER_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:5000';
const CRYPTO_SECRET_KEY = process.env.REACT_APP_SECRET_KEY || 'mySecretKey';

const websocketConnection = io(SERVER_URL);

const encryptionCache = {};
const decryptionCache = {};

function encryptText(text) {
    if (encryptionCache[text]) {
        return encryptionCache[text];
    }
  
    const encryptedText = CryptoJS.AES.encrypt(text, CRYPTO_SECRET_KEY).toString();
    encryptionCache[text] = encryptedText;
  
    return encryptedText;
}

function decryptText(encryptedText) {
    if (decryptionCache[encryptedText]) {
        return decryptionCache[encryptedText];
    }
  
    const decryptedBytes = CryptoJS.AES.decrypt(encryptedText, CRYPTO_SECRET_KEY);
    const decryptedText = decryptedBytes.toString(CryptoJS.enc.Utf8);
    decryptionCache[encryptedText] = decryptedText;
  
    return decryptedText;
}

function transmitEncryptedMessage(messageContent) {
    const encryptedMessage = encryptText(messageContent);
    websocketConnection.emit('sendMessage', encryptedMessage);
}

function displayEncryptedMessage(encryptedMessageContent) {
    console.log("Received message:", encryptedMessageContent);
}

function configureSendButtonListener() {
    document.getElementById('sendButton').addEventListener('click', () => {
        const userInput = document.getElementById('messageInput').value;
        transmitEncryptedMessage(userInput);
        document.getElementById('messageInput').value = '';
    });
}

function retrieveAndDisplayMessages() {
    fetch(`${SERVER_URL}/messages`)
        .then(response => response.json())
        .then(data => data.forEach(encryptedMsg => displayEncryptedMessage(decryptText(encryptedMsg))))
        .catch(error => console.error("Error fetching messages:", error));
}

function initializeWebSocketEvents() {
    websocketConnection.on('receiveMessage', encryptedMessage => {
        displayEncryptedMessage(decryptText(encryptedMessage));
    });
}

function initializeChat() {
    configureSendButtonListener();
    initializeWebSocketEvents();
    retrieveAndDisplayMessages();
}

initializeChat();