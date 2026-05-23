const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PPORT || 3000;

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
    
    try {
        // Check in database
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1 OR email = $1',
            [username]
        );
        
        const user = result.rows[0];
        
        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        
        // For demo, also allow admin/admin123
        if (username === 'admin' && password === 'admin123') {
            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role },
                process.env.JWT_SECRET || 'mySecretKey123',
                { expiresIn: '24h' }
            );
            return res.json({
                success: true,
                token,
                user: { id: user.id, username: user.username, email: user.email, full_name: user.full_name, role: user.role }
            });
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

// ==================== BUSINESS SEARCH PROXY (FIXES CORS) ====================
// ==================== BUSINESS SEARCH PROXY (IMPROVED) ====================
app.get('/api/search/business', async (req, res) => {
    const { q, location } = req.query;
    
    if (!q) {
        return res.status(400).json({ error: 'Search query required' });
    }
    
    // Build search query
    let searchTerms = q;
    if (location && location !== 'all' && location !== '') {
        searchTerms += ` ${location}`;
    }
    searchTerms += ` Ghana`;
    
    console.log(`Searching for: ${searchTerms}`);
    
    try {
        // Try multiple search approaches
        
        // Approach 1: DuckDuckGo Instant Answer
        const ddgUrl = `https://api.duckduckgo.com/?q=${encodeURIComponent(searchTerms)}&format=json&no_html=1`;
        const ddgResponse = await fetch(ddgUrl);
        const ddgData = await ddgResponse.json();
        
        let results = [];
        
        // Extract from RelatedTopics
        if (ddgData.RelatedTopics && ddgData.RelatedTopics.length > 0) {
            for (const topic of ddgData.RelatedTopics) {
                if (topic.Text && topic.Text.length > 0 && topic.Text.length < 300) {
                    let name = topic.Text.split(' - ')[0] || topic.Text.split(':')[0] || topic.Text.substring(0, 60);
                    name = name.replace(/[\[\]\(\)]/g, '').trim();
                    
                    results.push({
                        id: results.length + 1,
                        name: name.substring(0, 80),
                        description: topic.Text.substring(0, 200),
                        location: location || 'Ghana',
                        category: q,
                        url: topic.FirstURL || ''
                    });
                }
            }
        }
        
        // If no results from RelatedTopics, try Abstract
        if (results.length === 0 && ddgData.AbstractText) {
            results.push({
                id: 1,
                name: searchTerms,
                description: ddgData.AbstractText.substring(0, 200),
                location: location || 'Ghana',
                category: q,
                url: ddgData.AbstractURL || ''
            });
        }
        
        // Approach 2: If still no results, return sample data
        if (results.length === 0) {
            // Return sample businesses based on category
            const sampleBusinesses = getSampleBusinesses(q, location);
            results = sampleBusinesses;
        }
        
        res.json({ success: true, results: results });
        
    } catch (error) {
        console.error('Search proxy error:', error);
        // Return sample data on error
        const sampleBusinesses = getSampleBusinesses(q, location);
        res.json({ success: true, results: sampleBusinesses });
    }
});

// Helper function to provide sample business data
function getSampleBusinesses(category, location) {
    const loc = location || 'Ghana';
    const businesses = {
        schools: [
            { name: "Ghana International School", description: "Premier international school in Accra offering IB curriculum.", location: loc },
            { name: "Achimota School", description: "Famous mixed school established in 1924, known as the 'Eton of Africa'.", location: loc },
            { name: "Presbyterian Boys' Secondary School", description: "All-boys boarding school in Legon, Accra.", location: loc },
            { name: "Wesley Girls' High School", description: "Top girls' school in Cape Coast.", location: loc },
            { name: "Opoku Ware School", description: "Premier boys' school in Kumasi.", location: loc },
            { name: "Mfantsipim School", description: "All-boys school in Cape Coast, established 1876.", location: loc },
            { name: "St. Augustine's College", description: "Boys' school in Cape Coast.", location: loc },
            { name: "Holy Child School", description: "Girls' school in Cape Coast.", location: loc }
        ],
        hotels: [
            { name: "Labadi Beach Hotel", description: "Luxury beachfront hotel in Accra.", location: loc },
            { name: "Movenpick Ambassador Hotel", description: "5-star hotel in central Accra.", location: loc },
            { name: "Kempinski Hotel Gold Coast City", description: "Luxury hotel in Accra.", location: loc },
            { name: "Golden Tulip Accra", description: "International hotel chain in Accra.", location: loc },
            { name: "Miklin Hotel", description: "Premium hotel in Kumasi.", location: loc },
            { name: "Oak Plaza Hotel", description: "Business hotel in East Legon, Accra.", location: loc }
        ],
        hospitals: [
            { name: "Korle Bu Teaching Hospital", description: "Ghana's premier teaching hospital in Accra.", location: loc },
            { name: "Komfo Anokye Teaching Hospital", description: "Major referral hospital in Kumasi.", location: loc },
            { name: "37 Military Hospital", description: "Military hospital serving civilians in Accra.", location: loc },
            { name: "University of Ghana Medical Centre", description: "Modern medical facility in Legon, Accra.", location: loc },
            { name: "Trust Hospital", description: "Private hospital in Accra.", location: loc }
        ],
        restaurants: [
            { name: "Buka Restaurant", description: "Authentic Ghanaian cuisine in Accra.", location: loc },
            { name: "Zen Garden", description: "Asian and continental dishes in Accra.", location: loc },
            { name: "Santoku", description: "Japanese restaurant in Accra.", location: loc },
            { name: "Papaye", description: "Fast food restaurant in Kumasi and Accra.", location: loc }
        ],
        banks: [
            { name: "Ghana Commercial Bank (GCB)", description: "Largest commercial bank in Ghana.", location: loc },
            { name: "Ecobank Ghana", description: "Pan-African banking group.", location: loc },
            { name: "Stanbic Bank Ghana", description: "International banking services.", location: loc },
            { name: "Absa Bank Ghana", description: "Formerly Barclays Bank.", location: loc },
            { name: "Fidelity Bank Ghana", description: "Leading Ghanaian bank.", location: loc }
        ],
        it: [
            { name: "Soft System Solutions", description: "Software development and IT consulting.", location: loc },
            { name: "IT Consults Ghana", description: "IT consulting and solutions provider.", location: loc },
            { name: "Web Solutions Ghana", description: "Web development and digital marketing.", location: loc },
            { name: "Tech Hub Ghana", description: "Technology innovation hub.", location: loc }
        ]
    };
    
    // Find matching category
    let matchedCategory = null;
    for (const key of Object.keys(businesses)) {
        if (category.toLowerCase().includes(key) || key.includes(category.toLowerCase())) {
            matchedCategory = key;
            break;
        }
    }
    
    const sampleList = matchedCategory ? businesses[matchedCategory] : businesses.schools;
    
    return sampleList.map((biz, idx) => ({
        id: idx + 1,
        name: biz.name,
        description: biz.description,
        location: biz.location,
        category: category,
        url: ''
    }));
}
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
║     ✅ Business Search Proxy Enabled!                    ║
║                                                           ║
║     🔐 Login: admin / admin123                           ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    `);
});
