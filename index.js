const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const cookieParser = require('cookie-parser');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIO(server);

const USERS_DB = 'users.json';
const PORT = process.env.PORT || 3000;

// Utility: Read/Write Users
function readUsers() {
    if (!fs.existsSync(USERS_DB)) return [];
    return JSON.parse(fs.readFileSync(USERS_DB, 'utf-8'));
}
function writeUsers(users) {
    fs.writeFileSync(USERS_DB, JSON.stringify(users, null, 2));
}

// Serve static files
app.use(express.static(__dirname));
app.use(express.json());
app.use(cookieParser());

// Auth middleware
function authMiddleware(req, res, next) {
    const token = req.cookies['token'];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    const users = readUsers();
    const user = users.find(u => u.token === token);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    req.user = user;
    next();
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'chat.html'));
});
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'signup.html'));
});

// API: Sign Up
app.post('/api/signup', (req, res) => {
    const { username, password, remember } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
    const users = readUsers();
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ error: 'Username taken' });
    }
    const token = uuidv4();
    users.push({ username, password, token });
    writeUsers(users);
    res.cookie('token', token, { httpOnly: true, maxAge: remember ? 365*24*60*60*1000 : undefined });
    return res.json({ success: true });
});

// API: Login
app.post('/api/login', (req, res) => {
    const { username, password, remember } = req.body;
    const users = readUsers();
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    user.token = uuidv4();
    writeUsers(users);
    res.cookie('token', user.token, { httpOnly: true, maxAge: remember ? 365*24*60*60*1000 : undefined });
    return res.json({ success: true });
});

// API: Me
app.get('/api/me', authMiddleware, (req, res) => {
    res.json({ username: req.user.username });
});

// API: Logout
app.post('/api/logout', authMiddleware, (req, res) => {
    const users = readUsers();
    const user = users.find(u => u.username === req.user.username);
    if (user) user.token = '';
    writeUsers(users);
    res.clearCookie('token');
    res.json({ success: true });
});

// Socket.io
let messageHistory = [];

io.on('connection', (socket) => {
    // Auth via cookie
    let username = '';
    try {
        const { token } = socket.handshake.headers.cookie
            .split(';')
            .map(v => v.trim().split('='))
            .reduce((acc, [k, v]) => ({...acc, [k]: v}), {});
        const users = readUsers();
        const user = users.find(u => u.token === token);
        if (user) username = user.username;
    } catch (e) {}

    if (!username) {
        socket.emit('unauthorized');
        socket.disconnect();
        return;
    }

    // Send chat history
    socket.emit('history', messageHistory);

    // Broadcast join
    socket.broadcast.emit('message', {
        user: 'SYSTEM',
        text: `${username} has joined the chat.`,
        time: new Date().toISOString()
    });

    // Listen for messages
    socket.on('message', (data) => {
        const msg = {
            user: username,
            text: data.text,
            time: new Date().toISOString()
        };
        messageHistory.push(msg);
        if (messageHistory.length > 100) messageHistory.shift();
        io.emit('message', msg);
    });

    // Broadcast leave
    socket.on('disconnect', () => {
        socket.broadcast.emit('message', {
            user: 'SYSTEM',
            text: `${username} has left the chat.`,
            time: new Date().toISOString()
        });
    });
});

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});