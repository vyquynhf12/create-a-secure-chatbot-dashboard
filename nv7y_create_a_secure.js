const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const helmet = require('helmet');

// Secure chatbot dashboard configuration
const SECRET_KEY = 'my_secret_key';
const SALT_ROUNDS = 10;

// User database (in a real-world scenario, use a secure database like MongoDB or PostgreSQL)
const users = {
  'admin': 'hashed_admin_password',
};

// Hash password for new users
async function hashPassword(password) {
  return bcrypt.hash(password, SALT_ROUNDS);
}

// Verify password for existing users
async function verifyPassword(input, stored) {
  return bcrypt.compare(input, stored);
}

// Generate JWT token
function generateToken(username) {
  return jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
}

// Verify JWT token
function verifyToken(token) {
  return jwt.verify(token, SECRET_KEY);
}

app.use(express.json());
app.use(cors());
app.use(helmet());

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Invalid username or password' });
  }
  const storedPassword = users[username];
  if (!storedPassword) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  const isValid = await verifyPassword(password, storedPassword);
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  const token = generateToken(username);
  res.json({ token });
});

// Secure chatbot dashboard endpoint
app.get('/chatbot-dashboard', async (req, res) => {
  const token = req.header('Authorization');
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized access' });
  }
  try {
    const decoded = verifyToken(token);
    res.json({ message: `Welcome, ${decoded.username}!` });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(3000, () => {
  console.log('Secure chatbot dashboard running on port 3000');
});