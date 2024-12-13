const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const app = express();

// Middleware
app.use(express.json());

// Setup Database Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'mydb'
});

// Register Endpoint
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Please provide all fields' });
    }

    // Hash password before saving to DB
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).json({ message: 'Error hashing password' });

        const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
        db.query(query, [username, email, hashedPassword], (err, result) => {
            if (err) return res.status(500).json({ message: 'Error registering user' });

            res.status(201).json({ message: 'User registered successfully' });
        });
    });
});

// Login Endpoint
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Please provide both username and password' });
    }

    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (results.length === 0) return res.status(400).json({ message: 'User not found' });

        const user = results[0];

        // Compare password
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).json({ message: 'Error comparing passwords' });
            if (!isMatch) return res.status(400).json({ message: 'Invalid password' });

            // Create JWT token
            const token = jwt.sign(
                { userId: user.id, username: user.username },
                'your_secret_key', // Secret key to sign JWT
                { expiresIn: '1h' }
            );

            res.json({
                userId: user.id,
                username: user.username,
                token: token,
                iat: Math.floor(Date.now() / 1000),
                exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour expiry
            });
        });
    });
});

// Middleware to check if token is valid
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];

    if (!token) return res.status(403).json({ message: 'No token provided' });

    jwt.verify(token, 'your_secret_key', (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });

        req.user = user;
        next();
    });
};

// Endpoint that requires a valid JWT token
app.put('/update-email', authenticateToken, (req, res) => {
    const { email } = req.body;

    if (!email) return res.status(400).json({ message: 'Please provide an email' });

    const userId = req.user.userId;

    // Update user email based on userId from token
    const query = 'UPDATE users SET email = ? WHERE id = ?';
    db.query(query, [email, userId], (err, result) => {
        if (err) return res.status(500).json({ message: 'Error updating email' });

        res.json({ message: 'Email updated successfully' });
    });
});

// Start Server
app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
