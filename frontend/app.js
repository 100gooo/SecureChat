import io from 'socket.io-client';
import CryptoJS from 'crypto-js';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:5000';
const SECRET_KEY = process.env.REACT_APP_SECRET_KEY || 'mySecretKey';

const socket = io(BACKEND_URL);

function encryptMessage(message) {
    return CryptoJS.AES.encrypt(message, SECRET_KEY).toString();
}

function decryptMessage(ciphertext) {
    const bytes = CryptoJS.AES.decrypt(ciphertext, SECRET_KEY);
    return bytes.toString(CryptoJS.enc.Utf8);
}

function sendMessage(message) {
    const encryptedMsg = encryptMessage(message);
    socket.emit('sendMessage', encryptedMsg);
}

function displayMessage(message) {
    console.log("Received message:", message);
}

document.getElementById('sendButton').addEventListener('click', function () {
    const message = document.getElementById('messageInput').value;
    sendMessage(message);
    document.getElementById('messageInput').value = '';
});

function fetchMessages() {
    fetch(`${BACKEND_URL}/messages`)
        .then(response => response.json())
        .then(data => {
            data.forEach(msg => {
                const decryptedMsg = decryptMessage(msg);
                displayMessage(decryptedMsg);
            });
        })
        .catch(error => console.error("Error fetching messages:", error));
}

socket.on('receiveMessage', function (encryptedMsg) {
    const decryptedMsg = decryptMessage(encryptedMsg);
    displayMessage(decryptedMsg);
});

function init() {
    fetchMessages();
}

init();