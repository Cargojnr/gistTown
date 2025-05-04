const express = require("express");
const { WebSocket} = require("ws");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
    console.log('New client connected.');
    ws.on('message', (data) => {
        const message = JSON.parse(data);
        console.log(`Received: ${message.type} from ${message.user}`);

        // If it's a typing or stoppedTyping event, broadcast it to all connected clients
        if (message.type === 'typing' || message.type === 'stoppedTyping') {
            // Broadcast the typing status to all other clients
            wss.clients.forEach((client) => {
                if (client !== ws && client.readyState === WebSocket.OPEN) {
                    client.send(JSON.stringify(message)); // Send the typing status
                }
            });
        }

        // For regular chat messages
        if (message.type === 'message') {
            // Broadcast the message to all connected clients
            wss.clients.forEach((client) => {
                if (client !== ws && client.readyState === WebSocket.OPEN) {
                    client.send(JSON.stringify(message)); // Broadcast the chat message
                }
            });
        }
    });

    ws.on('close', () => {
        console.log('Client disconnected.');
    });
});

module.exports = { wss, server };