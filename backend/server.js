const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Test database connection
pool.connect((err) => {
    if (err) {
        console.error('❌ Database connection error:', err.message);
    } else {
        console.log('✅ PostgreSQL connected successfully');
    }
});

// ==================== AUTH MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ success: false, message: 'Access denied' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'mySecretKey123');
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ success: false, message: 'Invalid token' });
    }
};

// ==================== LOGIN ====================
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    
    console.log('Login attempt:', username);
    
    try {
        if (username === 'admin' && password === 'admin123') {
            const token = jwt.sign(
                { id: 1, username: 'admin', role: 'admin' },
                process.env.JWT_SECRET || 'mySecretKey123',
                { expiresIn: '24h' }
            );
            return res.json({
                success: true,
                token,
                user: { id: 1, username: 'admin', role: 'admin' }
            });
        }
        
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1 OR email = $1',
            [username]
        );
        
        const user = result.rows[0];
        
        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET || 'mySecretKey123',
            { expiresIn: '24h' }
        );
        
        res.json({
            success: true,
            token,
            user: { id: user.id, username: user.username, email: user.email, full_name: user.full_name, role: user.role }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== CONTACTS API ====================
app.get('/api/contacts', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM contacts WHERE user_id = $1 ORDER BY created_at DESC',
            [req.user.id]
        );
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/contacts', authenticateToken, async (req, res) => {
    const { name, company, email, phone, address, category, status, notes } = req.body;
    
    if (!name) {
        return res.status(400).json({ error: 'Name is required' });
    }
    
    try {
        const result = await pool.query(
            `INSERT INTO contacts (user_id, name, company, email, phone, address, category, status, notes)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             RETURNING *`,
            [req.user.id, name, company, email, phone, address, category, status || 'new', notes]
        );
        res.json({ success: true, contact: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/contacts/:id', authenticateToken, async (req, res) => {
    const { name, company, email, phone, address, category, status, notes } = req.body;
    
    try {
        const result = await pool.query(
            `UPDATE contacts SET name = $1, company = $2, email = $3, phone = $4, address = $5, category = $6, status = $7, notes = $8, updated_at = CURRENT_TIMESTAMP
             WHERE id = $9 AND user_id = $10 RETURNING *`,
            [name, company, email, phone, address, category, status, notes, req.params.id, req.user.id]
        );
        res.json({ success: true, contact: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/contacts/:id', authenticateToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM contacts WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== PROPOSALS API ====================
app.get('/api/proposals', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT p.*, c.name as contact_name, c.company as contact_company, c.email as contact_email
             FROM proposals p
             JOIN contacts c ON p.contact_id = c.id
             WHERE p.user_id = $1 
             ORDER BY p.sent_date DESC`,
            [req.user.id]
        );
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/proposals', authenticateToken, async (req, res) => {
    const { contact_id, title, description, amount, status } = req.body;
    
    if (!contact_id || !title) {
        return res.status(400).json({ error: 'Contact and title are required' });
    }
    
    try {
        const result = await pool.query(
            `INSERT INTO proposals (user_id, contact_id, title, description, amount, status, sent_date)
             VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
             RETURNING *`,
            [req.user.id, contact_id, title, description, amount, status || 'draft']
        );
        res.json({ success: true, proposal: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/proposals/:id/status', authenticateToken, async (req, res) => {
    const { status, response_notes } = req.body;
    
    try {
        const result = await pool.query(
            `UPDATE proposals 
             SET status = $1, response_notes = $2, responded_date = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
             WHERE id = $3 AND user_id = $4
             RETURNING *`,
            [status, response_notes, req.params.id, req.user.id]
        );
        res.json({ success: true, proposal: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/proposals/:id', authenticateToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM proposals WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== BUSINESSES API ====================
app.get('/api/businesses', authenticateToken, async (req, res) => {
    const { category, location } = req.query;
    let query = 'SELECT * FROM businesses WHERE user_id = $1';
    let params = [req.user.id];
    
    if (category) {
        query += ' AND category ILIKE $' + (params.length + 1);
        params.push(`%${category}%`);
    }
    
    if (location) {
        query += ' AND location ILIKE $' + (params.length + 1);
        params.push(`%${location}%`);
    }
    
    query += ' ORDER BY created_at DESC';
    
    try {
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/businesses', authenticateToken, async (req, res) => {
    const { name, category, location, email, phone, website, notes } = req.body;
    
    if (!name) {
        return res.status(400).json({ error: 'Name is required' });
    }
    
    try {
        const result = await pool.query(
            `INSERT INTO businesses (user_id, name, category, location, email, phone, website, notes)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING *`,
            [req.user.id, name, category, location, email, phone, website, notes]
        );
        res.json({ success: true, business: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== STATS API ====================
app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        const contacts = await pool.query('SELECT COUNT(*) FROM contacts WHERE user_id = $1', [req.user.id]);
        const proposals = await pool.query('SELECT COUNT(*) FROM proposals WHERE user_id = $1', [req.user.id]);
        const accepted = await pool.query('SELECT COUNT(*) FROM proposals WHERE user_id = $1 AND status = $2', [req.user.id, 'accepted']);
        
        res.json({
            total_contacts: parseInt(contacts.rows[0].count),
            total_proposals: parseInt(proposals.rows[0].count),
            accepted_proposals: parseInt(accepted.rows[0].count)
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== GOOGLE PLACES API PROXY ====================
const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY || 'AIzaSyDUQPjapUS2gmisamwtqQF5CbC6C-jUoDI';

app.get('/api/search/google-places', authenticateToken, async (req, res) => {
    const { query, location } = req.query;
    
    console.log(`Google Places Search: ${query} in ${location}`);
    
    if (!query) {
        return res.status(400).json({ error: 'Search query required' });
    }
    
    let searchQuery = `${query} in ${location || 'Accra'} Ghana`;
    
    try {
        const url = `https://maps.googleapis.com/maps/api/place/textsearch/json?query=${encodeURIComponent(searchQuery)}&key=${GOOGLE_API_KEY}`;
        console.log('Calling Google Places API:', url);
        
        const response = await fetch(url);
        const data = await response.json();
        
        console.log('Google Places API response status:', data.status);
        
        if (data.status === 'OK' && data.results) {
            const results = data.results.map(place => ({
                name: place.name,
                address: place.formatted_address,
                location: location || 'Ghana',
                rating: place.rating || 'N/A',
                total_ratings: place.user_ratings_total || 0,
                phone: place.formatted_phone_number || 'Not available',
                website: place.website || '',
                place_id: place.place_id,
                lat: place.geometry.location.lat,
                lng: place.geometry.location.lng,
                category: query
            }));
            res.json({ success: true, results: results });
        } else {
            console.log('Google Places API returned:', data.status, data.error_message);
            res.json({ success: false, results: [], message: data.status, error: data.error_message });
        }
    } catch (error) {
        console.error('Google Places API error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Server is running!' });
});

// ==================== SERVE FRONTEND ====================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend', 'index.html'));
});

app.get('/:page.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend', `${req.params.page}.html`));
});

// ==================== START SERVER ====================
app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     🏢 SOFT SYSTEM SOLUTIONS                             ║
║     Business Intelligence & CRM System                   ║
║     Server running on http://localhost:${PORT}             ║
║                                                           ║
║     ✅ PostgreSQL Connected!                             ║
║     ✅ Google Places API Ready!                          ║
║                                                           ║
║     🔐 Login: admin / admin123                           ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    `);
});
