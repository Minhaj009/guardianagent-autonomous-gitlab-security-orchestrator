const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Setup Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configure Express Session
app.use(session({
    secret: 'guardian_agent_secret_key_12345',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Set to true if running over HTTPS
        maxAge: 1000 * 60 * 60 * 24 // 1 day
    }
}));

// Set EJS as templating engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Authentication Middleware
function checkAuth(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    }
    res.redirect('/login');
}

// Redirect root to dashboard
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

// GET Login / Signup page
app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.render('login', { error: null, success: null });
});

// POST Signup
app.post('/signup', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.render('login', { error: 'Please enter all fields.', success: null });
    }

    // Hash password
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            console.error('Bcrypt error:', err);
            return res.render('login', { error: 'Signup failed. Please try again.', success: null });
        }

        const guardianUserId = 'usr_' + crypto.randomBytes(6).toString('hex');

        db.run(
            'INSERT INTO users (email, password_hash, guardian_user_id) VALUES (?, ?, ?)',
            [email, hash, guardianUserId],
            function (err2) {
                if (err2) {
                    if (err2.message.includes('UNIQUE constraint failed')) {
                        return res.render('login', { error: 'Email already registered.', success: null });
                    }
                    return res.render('login', { error: 'Signup failed: ' + err2.message, success: null });
                }
                res.render('login', { error: null, success: 'Account created successfully! Please login.' });
            }
        );
    });
});

// POST Login
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.render('login', { error: 'Please enter all fields.', success: null });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.render('login', { error: 'Login failed. Database error.', success: null });
        }
        if (!user) {
            return res.render('login', { error: 'Invalid email or password.', success: null });
        }

        bcrypt.compare(password, user.password_hash, (err2, isMatch) => {
            if (err2) {
                console.error('Bcrypt compare error:', err2);
                return res.render('login', { error: 'Login failed. Comparison error.', success: null });
            }
            if (!isMatch) {
                return res.render('login', { error: 'Invalid email or password.', success: null });
            }

            // Set session variables
            req.session.userId = user.id;
            req.session.userEmail = user.email;
            res.redirect('/dashboard');
        });
    });
});

// GET Dashboard
app.get('/dashboard', checkAuth, (req, res) => {
    const userId = req.session.userId;
    const userEmail = req.session.userEmail;

    db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            console.error('DB error fetching user:', err);
            return res.status(500).send('Internal Server Error');
        }

        const guardianUserId = user ? user.guardian_user_id : 'usr_demo';
        const rawKey = user ? user.openrouter_key : '';
        let maskedKey = '';
        if (rawKey) {
            maskedKey = rawKey.substring(0, 7) + '****************' + rawKey.substring(rawKey.length - 4);
        }

        // Fetch user's own scans
        db.all('SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC', [userId], (err2, userScans) => {
            if (err2) {
                console.error('DB error fetching scans:', err2);
                return res.status(500).send('Internal Server Error');
            }

            // Determine if using demo mode or live mode
            const isDemoMode = userScans.length === 0;

            if (isDemoMode) {
                // Fetch default demo scans
                db.all('SELECT * FROM scans WHERE user_id IS NULL ORDER BY created_at DESC', (err3, demoScans) => {
                    if (err3) {
                        console.error('DB error fetching demo scans:', err3);
                        return res.status(500).send('Internal Server Error');
                    }
                    res.render('dashboard', {
                        userEmail,
                        userId,
                        guardianUserId,
                        maskedKey,
                        scans: demoScans,
                        isDemoMode: true,
                        activeTab: 'dashboard',
                        currentPath: '/dashboard'
                    });
                });
            } else {
                res.render('dashboard', {
                    userEmail,
                    userId,
                    guardianUserId,
                    maskedKey,
                    scans: userScans,
                    isDemoMode: false,
                    activeTab: 'dashboard',
                    currentPath: '/dashboard'
                });
            }
        });
    });
});

// GET GitHub Setup
app.get('/setup/github', checkAuth, (req, res) => {
    const userId = req.session.userId;
    const userEmail = req.session.userEmail;

    db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            console.error('DB error fetching user:', err);
            return res.status(500).send('Internal Server Error');
        }

        const guardianUserId = user ? user.guardian_user_id : 'usr_demo';
        res.render('github', {
            userEmail,
            guardianUserId,
            activeTab: 'github',
            currentPath: '/setup/github'
        });
    });
});

// GET GitLab Setup
app.get('/setup/gitlab', checkAuth, (req, res) => {
    const userId = req.session.userId;
    const userEmail = req.session.userEmail;

    db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            console.error('DB error fetching user:', err);
            return res.status(500).send('Internal Server Error');
        }

        const guardianUserId = user ? user.guardian_user_id : 'usr_demo';
        res.render('gitlab', {
            userEmail,
            guardianUserId,
            activeTab: 'gitlab',
            currentPath: '/setup/gitlab'
        });
    });
});

// POST Settings Update API Key
app.post('/settings/update-key', checkAuth, (req, res) => {
    const userId = req.session.userId;
    const { openrouter_key } = req.body;

    if (!openrouter_key) {
        return res.status(400).send('Key cannot be empty.');
    }

    db.run(
        'UPDATE users SET openrouter_key = ? WHERE id = ?',
        [openrouter_key, userId],
        function (err) {
            if (err) {
                console.error('DB error updating key:', err);
                return res.status(500).send('Failed to save key.');
            }
            res.redirect('/dashboard?key_updated=true');
        }
    );
});

// GET API for repository findings (to support live UI switches)
app.get('/api/scans/:repo', checkAuth, (req, res) => {
    const repo = req.params.repo;
    const userId = req.session.userId;

    // Fetch findings for the specified repo
    // Try user's own scans first. If none, search from global demo scans (user_id IS NULL)
    db.all('SELECT * FROM scans WHERE user_id = ? AND repo_name = ? ORDER BY line DESC', [userId, repo], (err, rows) => {
        if (err) {
            console.error('DB error:', err);
            return res.status(500).json({ error: 'DB Error' });
        }

        if (rows.length > 0) {
            return res.json({ scans: rows, mode: 'live' });
        }

        // Fallback to demo scans
        db.all('SELECT * FROM scans WHERE user_id IS NULL AND repo_name = ? ORDER BY line DESC', [repo], (err2, demoRows) => {
            if (err2) {
                console.error('DB error:', err2);
                return res.status(500).json({ error: 'DB Error' });
            }
            res.json({ scans: demoRows, mode: 'demo' });
        });
    });
});

// POST API to receive scans reported by the runner CLI
app.post('/api/scans/report', (req, res) => {
    const { guardian_user_id, repo_name, scans } = req.body;

    if (!guardian_user_id || !repo_name || !scans) {
        return res.status(400).json({ error: 'Missing required fields: guardian_user_id, repo_name, or scans.' });
    }

    // Find user by guardian_user_id
    db.get('SELECT id FROM users WHERE guardian_user_id = ?', [guardian_user_id], (err, user) => {
        if (err) {
            console.error('DB error finding user:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (!user) {
            return res.status(404).json({ error: 'User not found with the provided guardian_user_id.' });
        }

        const userId = user.id;

        // Delete old scans for this repository under this user
        db.run('DELETE FROM scans WHERE user_id = ? AND repo_name = ?', [userId, repo_name], (errDel) => {
            if (errDel) {
                console.error('DB error deleting old scans:', errDel);
                return res.status(500).json({ error: 'Failed to clear old scans.' });
            }

            // Insert new scans
            const stmt = db.prepare(`
                INSERT INTO scans (user_id, repo_name, file, line, consensus_score, vulnerability, description, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `);

            scans.forEach(s => {
                stmt.run(userId, repo_name, s.file, s.line, s.consensus_score, s.vulnerability, s.description, s.status);
            });

            stmt.finalize((errFinal) => {
                if (errFinal) {
                    console.error('DB error finalizing scans insert:', errFinal);
                    return res.status(500).json({ error: 'Failed to record scan results.' });
                }
                res.json({ success: true, message: `Successfully recorded ${scans.length} scans.` });
            });
        });
    });
});

// GET Logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
        }
        res.redirect('/login');
    });
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});
