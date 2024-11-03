import io from 'socket.io-client';
import CryptoJS from 'crypto-js';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:5000';
const SECRET_KEY = process.env.REACT_APP_SECRET_KEY || 'mySecretKey';

const socket = io(BACKEND_URL);

const encryptCache = {};
const decryptCache = {};

function encryptMessage(message) {
    // Check cache first
    if (encryptCache[message]) {
        return encryptCache[message];
    }
  
    const encryptedMessage = CryptoJS.AES.encrypt(message, SECRET_KEY).toString();
    // Cache the result before returning
    encryptCache[message] = encryptedMessage;
  
    return encryptedMessage;
}

function decryptMessage(ciphertext) {
    // Check cache first
    if (decryptCache[ciphertext]) {
        return decryptCache[ciphertext];
    }
  
    const bytes = CryptoJS.AES.decrypt(ciphertext, SECRET_KEY);
    const decryptedMessage = bytes.toString(CryptoJS.enc.Utf8);
    // Cache the result before returning
    decryptCache[ciphertext] = decryptedMessage;
  
    return decryptedMessage;
}

function sendMessage(message) {
    const encryptedMsg = encryptMessage(message);
    socket.emit('sendMessage', encryptedMsg);
}

function displayMessage(message) {
    console.log("Received message:", message);
}

function setupSendMessageButton() {
    document.getElementById('sendButton').addEventListener('click', () => {
        const message = document.getElementById('messageInput').value;
        sendMessage(message);
        document.getElementById('messageInput').value = '';
    });
}

function fetchMessages() {
    fetch(`${BACKEND_URL}/messages`)
        .then(response => response.json())
        .then(data => data.forEach(msg => displayMessage(decryptMessage(msg))))
        .catch(error => console.error("Error fetching messages:", error));
}

function setupSocketListeners() {
    socket.on('receiveMessage', encryptedMsg => {
        displayMessage(decryptMessage(encryptedMsg));
    });
}

function init() {
    setupSendMessageButton();
    setupSocketListeners();
    fetchMessages();
}

init();