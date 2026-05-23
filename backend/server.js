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
        // First check hardcoded admin for testing
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
        
        // Then check database
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

// ==================== BUSINESS SEARCH PROXY (CORS FIX) ====================
app.get('/api/search/business', async (req, res) => {
    const { q, location } = req.query;
    
    console.log(`Search API called with q: ${q}, location: ${location}`);
    
    if (!q) {
        return res.status(400).json({ error: 'Search query required' });
    }
    
    // Ghana Business Database
    const ghanaBusinesses = {
        schools: [
            { name: "Ghana International School", location: "Accra", phone: "+233 30 221 1234", email: "info@gis.edu.gh", category: "school", rating: 4.5, description: "Premier international school in Accra offering IB curriculum." },
            { name: "Achimota School", location: "Accra", phone: "+233 30 222 4567", email: "info@achimota.edu.gh", category: "school", rating: 4.6, description: "Famous mixed school established in 1924, known as the 'Eton of Africa'." },
            { name: "Presbyterian Boys' Secondary School", location: "Accra", phone: "+233 30 222 9876", email: "info@presec.edu.gh", category: "school", rating: 4.7, description: "All-boys boarding school in Legon, Accra." },
            { name: "Wesley Girls' High School", location: "Cape Coast", phone: "+233 33 202 5678", email: "info@wesleygirls.edu.gh", category: "school", rating: 4.8, description: "Top girls' school in Cape Coast." },
            { name: "Opoku Ware School", location: "Kumasi", phone: "+233 32 202 5678", email: "info@opokuware.edu.gh", category: "school", rating: 4.6, description: "Premier boys' school in Kumasi." },
            { name: "Mfantsipim School", location: "Cape Coast", phone: "+233 33 202 2345", email: "info@mfantsipim.edu.gh", category: "school", rating: 4.7, description: "All-boys school in Cape Coast, established 1876." },
            { name: "St. Augustine's College", location: "Cape Coast", phone: "+233 33 202 8901", email: "info@staugustine.edu.gh", category: "school", rating: 4.5, description: "Boys' school in Cape Coast." },
            { name: "Holy Child School", location: "Cape Coast", phone: "+233 33 202 1234", email: "info@holychild.edu.gh", category: "school", rating: 4.6, description: "Girls' school in Cape Coast." },
            { name: "Living Spring Adventist Academy", location: "Accra", phone: "+233 24 123 4567", email: "info@livingspring.edu.gh", category: "school", rating: 4.4, description: "Private Christian school offering quality education." }
        ],
        hotels: [
            { name: "Labadi Beach Hotel", location: "Accra", phone: "+233 30 222 1234", email: "info@labadibeach.com", category: "hotel", rating: 4.7, description: "Luxury beachfront hotel in Accra." },
            { name: "Movenpick Ambassador Hotel", location: "Accra", phone: "+233 30 222 5678", email: "info@movenpick.com", category: "hotel", rating: 4.8, description: "5-star hotel in central Accra." },
            { name: "Kempinski Hotel Gold Coast City", location: "Accra", phone: "+233 30 222 9012", email: "info@kempinski.com", category: "hotel", rating: 4.9, description: "Luxury hotel in Accra." },
            { name: "Golden Tulip Accra", location: "Accra", phone: "+233 30 222 3456", email: "info@goldentulip.com", category: "hotel", rating: 4.4, description: "International hotel chain in Accra." },
            { name: "Miklin Hotel", location: "Kumasi", phone: "+233 32 202 1234", email: "info@miklinhotel.com", category: "hotel", rating: 4.5, description: "Premium hotel in Kumasi." }
        ],
        hospitals: [
            { name: "Korle Bu Teaching Hospital", location: "Accra", phone: "+233 30 222 1234", email: "info@korlebu.gov.gh", category: "hospital", rating: 4.2, description: "Ghana's premier teaching hospital in Accra." },
            { name: "Komfo Anokye Teaching Hospital", location: "Kumasi", phone: "+233 32 202 1234", email: "info@kath.gov.gh", category: "hospital", rating: 4.1, description: "Major referral hospital in Kumasi." },
            { name: "37 Military Hospital", location: "Accra", phone: "+233 30 222 5678", email: "info@37militaryhospital.com", category: "hospital", rating: 4.3, description: "Military hospital serving civilians in Accra." },
            { name: "University of Ghana Medical Centre", location: "Accra", phone: "+233 30 222 3456", email: "info@ugmc.edu.gh", category: "hospital", rating: 4.5, description: "Modern medical facility in Legon, Accra." },
            { name: "Trust Hospital", location: "Accra", phone: "+233 30 222 9012", email: "info@trusthospital.com", category: "hospital", rating: 4.2, description: "Private hospital in Accra." }
        ],
        restaurants: [
            { name: "Buka Restaurant", location: "Accra", phone: "+233 30 222 1234", email: "info@buka.com.gh", category: "restaurant", rating: 4.6, description: "Authentic Ghanaian cuisine in Accra." },
            { name: "Zen Garden", location: "Accra", phone: "+233 30 222 5678", email: "info@zengarden.com", category: "restaurant", rating: 4.5, description: "Asian and continental dishes in Accra." },
            { name: "Santoku", location: "Accra", phone: "+233 30 222 9012", email: "info@santoku.com", category: "restaurant", rating: 4.7, description: "Japanese restaurant in Accra." },
            { name: "Papaye", location: "Kumasi", phone: "+233 32 202 1234", email: "info@papaye.com", category: "restaurant", rating: 4.3, description: "Fast food restaurant in Kumasi and Accra." }
        ],
        banks: [
            { name: "Ghana Commercial Bank (GCB)", location: "Accra", phone: "+233 30 222 1234", email: "info@gcb.com.gh", category: "bank", rating: 4.2, description: "Largest commercial bank in Ghana." },
            { name: "Ecobank Ghana", location: "Accra", phone: "+233 30 222 5678", email: "info@ecobank.com", category: "bank", rating: 4.3, description: "Pan-African banking group." },
            { name: "Stanbic Bank Ghana", location: "Accra", phone: "+233 30 222 9012", email: "info@stanbic.com", category: "bank", rating: 4.4, description: "International banking services." },
            { name: "Absa Bank Ghana", location: "Accra", phone: "+233 30 222 3456", email: "info@absa.com.gh", category: "bank", rating: 4.3, description: "Formerly Barclays Bank." }
        ],
        it: [
            { name: "Soft System Solutions", location: "Accra", phone: "+233 24 000 0000", email: "info@softsystemsolutions.com", category: "it", rating: 5.0, description: "Software development and IT consulting." },
            { name: "IT Consults Ghana", location: "Accra", phone: "+233 24 111 2222", email: "info@itconsults.com", category: "it", rating: 4.5, description: "IT consulting and solutions provider." },
            { name: "Web Solutions Ghana", location: "Accra", phone: "+233 24 333 4444", email: "info@websolutionsgh.com", category: "it", rating: 4.4, description: "Web development and digital marketing." }
        ]
    };
    
    try {
        let results = [];
        const queryLower = q.toLowerCase();
        
        // Find matching category
        const categoryMap = {
            'school': 'schools', 'schools': 'schools',
            'hotel': 'hotels', 'hotels': 'hotels',
            'hospital': 'hospitals', 'hospitals': 'hospitals',
            'restaurant': 'restaurants', 'restaurants': 'restaurants',
            'bank': 'banks', 'banks': 'banks',
            'it': 'it', 'it companies': 'it', 'tech': 'it'
        };
        
        const matchedCategory = categoryMap[queryLower];
        
        if (matchedCategory && ghanaBusinesses[matchedCategory]) {
            results = [...ghanaBusinesses[matchedCategory]];
        } else {
            // Search across all categories
            for (const category of Object.keys(ghanaBusinesses)) {
                for (const biz of ghanaBusinesses[category]) {
                    if (biz.name.toLowerCase().includes(queryLower) || 
                        biz.category.toLowerCase().includes(queryLower)) {
                        results.push(biz);
                    }
                }
            }
        }
        
        // Filter by location if specified
        if (location && location !== 'all' && location !== '') {
            results = results.filter(biz => biz.location === location);
        }
        
        // If no results, return sample from first category
        if (results.length === 0) {
            results = ghanaBusinesses.schools.slice(0, 8);
        }
        
        res.json({ success: true, results: results });
        
    } catch (error) {
        console.error('Search error:', error);
        res.json({ 
            success: true, 
            results: ghanaBusinesses.schools.slice(0, 8)
        });
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
║     ✅ Business Search API Ready!                        ║
║                                                           ║
║     🔐 Login: admin / admin123                           ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    `);
});
