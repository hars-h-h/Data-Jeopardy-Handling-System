require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('../client'));

// MySQL Connection Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'security_dashboard',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// API Routes
app.get('/api/health', (req, res) => {
    res.json({ status: 'Server is running' });
});

app.get('/api/events', async (req, res) => {
    try {
        const connection = await pool.getConnection();
        const [rows] = await connection.query('SELECT * FROM security_events LIMIT 100');
        connection.release();
        res.json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch events' });
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`Security Dashboard running on port ${PORT}`);
    console.log(`Visit http://localhost:${PORT} to access the dashboard`);
});
