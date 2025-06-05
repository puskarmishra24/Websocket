const WebSocket = require('ws');
const server = new WebSocket.Server({ port: 8081 });
server.on('connection', (ws) => {
    ws.on('message', (msg) => ws.send(`Echo: ${msg}`));
    console.log('Client connected');
});
console.log('Server running at ws://localhost:8081');