const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');
const db = require('./database');
const https = require('https');
const { spawn } = require('child_process');

// Configuration for service credentials encryption
const ENCRYPTION_KEY = process.env.SECRET_ENCRYPTION_KEY || 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'; // 32 characters key
const IV_LENGTH = 16;

function encrypt(text) {
    if (!text) return '';
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return '';
    try {
        let textParts = text.split(':');
        let iv = Buffer.from(textParts.shift(), 'hex');
        let encryptedText = Buffer.from(textParts.join(':'), 'hex');
        let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (e) {
        console.error('Decryption failed:', e);
        return '';
    }
}

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

// Helper to guarantee every logged-in user has a guardian_user_id
function getOrGenerateGuardianUserId(user, callback) {
    if (!user) {
        return callback(null, 'usr_demo');
    }
    if (user.guardian_user_id) {
        return callback(null, user.guardian_user_id);
    }
    const newId = 'usr_' + crypto.randomBytes(6).toString('hex');
    db.run('UPDATE users SET guardian_user_id = ? WHERE id = ?', [newId, user.id], (err) => {
        if (err) {
            console.error('Failed to update guardian_user_id:', err);
        }
        user.guardian_user_id = newId;
        callback(null, newId);
    });
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

        getOrGenerateGuardianUserId(user, (errId, guardianUserId) => {
            // Fetch user's own scans
            db.all('SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC', [userId], (err2, userScans) => {
                if (err2) {
                    console.error('DB error fetching scans:', err2);
                    return res.status(500).send('Internal Server Error');
                }

                db.all('SELECT repo_name FROM user_repos WHERE user_id = ? AND is_active = 1', [userId], (errRepos, activeRepos) => {
                    if (errRepos) {
                        console.error('DB error fetching user repos:', errRepos);
                        return res.status(500).send('Internal Server Error');
                    }
                    const seen = new Set();
                    const repos = [];
                    if (activeRepos) {
                        activeRepos.forEach(r => {
                            const lower = r.repo_name.toLowerCase();
                            if (!seen.has(lower)) {
                                seen.add(lower);
                                repos.push(r.repo_name);
                            }
                        });
                    }
                    res.render('dashboard', {
                        userEmail,
                        userId,
                        guardianUserId,
                        scans: userScans,
                        activeRepos: repos,
                        isDemoMode: false,
                        activeTab: 'dashboard',
                        currentPath: '/dashboard'
                    });
                });
            });
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

        getOrGenerateGuardianUserId(user, (errId, guardianUserId) => {
            const hasGitlabToken = user && user.gitlab_token ? true : false;
            res.render('gitlab', {
                userEmail,
                guardianUserId,
                hasGitlabToken,
                activeTab: 'gitlab',
                currentPath: '/setup/gitlab'
            });
        });
    });
});

// POST Settings Update GitLab configuration
app.post('/settings/update-gitlab', checkAuth, (req, res) => {
    const userId = req.session.userId;
    const { gitlab_token } = req.body;

    if (!gitlab_token) {
        return res.status(400).send('GitLab Token cannot be empty.');
    }

    if (gitlab_token === 'disconnect') {
        db.run(
            'UPDATE users SET gitlab_token = NULL WHERE id = ?',
            [userId],
            function (err) {
                if (err) {
                    console.error('DB error disconnecting GitLab:', err);
                    return res.status(500).send('Failed to disconnect.');
                }
                res.redirect('/setup/gitlab?disconnected=true');
            }
        );
    } else {
        const encryptedToken = encrypt(gitlab_token);
        db.run(
            'UPDATE users SET gitlab_token = ? WHERE id = ?',
            [encryptedToken, userId],
            function (err) {
                if (err) {
                    console.error('DB error updating GitLab token:', err);
                    return res.status(500).send('Failed to save configuration.');
                }
                res.redirect('/setup/gitlab?updated=true');
            }
        );
    }
});

// GET API to fetch user's GitLab projects
app.get('/api/gitlab/projects', checkAuth, async (req, res) => {
    const userId = req.session.userId;

    db.get('SELECT gitlab_token FROM users WHERE id = ?', [userId], async (err, user) => {
        if (err || !user || !user.gitlab_token) {
            return res.status(400).json({ error: 'GitLab account is not connected yet.' });
        }

        const token = decrypt(user.gitlab_token);
        if (!token) {
            return res.status(500).json({ error: 'Failed to decrypt GitLab token.' });
        }

        try {
            const fetchRes = await fetch('https://gitlab.com/api/v4/projects?membership=true&simple=true&per_page=100', {
                headers: {
                    'PRIVATE-TOKEN': token
                }
            });

            if (!fetchRes.ok) {
                return res.status(fetchRes.status).json({ error: 'Failed to retrieve projects from GitLab API.' });
            }

            const projects = await fetchRes.json();
            console.log(`Successfully fetched ${projects.length} projects from GitLab API.`);

            // Fetch active repositories for this user from database
            db.all('SELECT repo_name, is_active FROM user_repos WHERE user_id = ?', [userId], (err2, activeRepos) => {
                if (err2) {
                    console.error('DB error fetching user repos:', err2);
                    return res.status(500).json({ error: 'Database error' });
                }

                const activeSet = new Set(activeRepos.filter(r => r.is_active === 1).map(r => r.repo_name));
                const projectsWithStatus = projects.map(p => ({
                    id: p.id,
                    name: p.name,
                    path_with_namespace: p.path_with_namespace,
                    web_url: p.web_url,
                    is_active: activeSet.has(p.path_with_namespace)
                }));

                res.json({ success: true, projects: projectsWithStatus });
            });

        } catch (ex) {
            console.error('Exception fetching GitLab projects:', ex);
            res.status(500).json({ error: 'Internal Server Error fetching GitLab projects.' });
        }
    });
});

// POST API to toggle active repository status
app.post('/api/gitlab/toggle-repo', checkAuth, (req, res) => {
    const userId = req.session.userId;
    const { repo_name, repo_id, is_active } = req.body;

    if (!repo_name) {
        return res.status(400).json({ error: 'Repository name is required.' });
    }

    const isActiveVal = is_active ? 1 : 0;

    db.get('SELECT id FROM user_repos WHERE user_id = ? AND LOWER(repo_name) = LOWER(?)', [userId, repo_name], (err, row) => {
        if (err) {
            console.error('DB error finding repo:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (row) {
            db.run(
                'UPDATE user_repos SET is_active = ? WHERE id = ?',
                [isActiveVal, row.id],
                function (errUp) {
                    if (errUp) {
                        return res.status(500).json({ error: 'Failed to update repository status.' });
                    }
                    res.json({ success: true, is_active: isActiveVal === 1 });
                }
            );
        } else {
            db.run(
                'INSERT INTO user_repos (user_id, repo_name, repo_id, is_active) VALUES (?, ?, ?, ?)',
                [userId, repo_name, repo_id || null, isActiveVal],
                function (errIn) {
                    if (errIn) {
                        return res.status(500).json({ error: 'Failed to connect repository.' });
                    }
                    res.json({ success: true, is_active: isActiveVal === 1 });
                }
            );
        }
    });
});

// POST Settings Update GCP configuration
app.post('/settings/update-gcp', checkAuth, (req, res) => {
    const userId = req.session.userId;
    const { gcp_project_id, gcp_location, gcp_credentials } = req.body;
    const auto_remediation = req.body.auto_remediation === 'true' ? 1 : 0;

    if (!gcp_project_id || !gcp_location) {
        return res.status(400).send('GCP Project ID and Location cannot be empty.');
    }

    const encryptedCreds = gcp_credentials ? encrypt(gcp_credentials) : null;

    db.run(
        'UPDATE users SET gcp_project_id = ?, gcp_location = ?, gcp_credentials = ?, auto_remediation = ? WHERE id = ?',
        [gcp_project_id, gcp_location, encryptedCreds, auto_remediation, userId],
        function (err) {
            if (err) {
                console.error('DB error updating GCP config:', err);
                return res.status(500).send('Failed to save configuration.');
            }
            res.redirect('/dashboard?gcp_updated=true');
        }
    );
});

// GET API for repository findings (to support live UI switches)
app.get('/api/scans/:repo(*)', checkAuth, (req, res) => {
    const repo = req.params.repo;
    const userId = req.session.userId;

    // Check if the repo is in the user's own active repos (case-insensitive)
    db.get('SELECT id FROM user_repos WHERE user_id = ? AND LOWER(repo_name) = LOWER(?) AND is_active = 1', [userId, repo], (err, repoRow) => {
        if (err) {
            console.error('DB error checking user repos:', err);
            return res.status(500).json({ error: 'DB Error' });
        }

        if (repoRow) {
            // User repository: only fetch user's own scans (no demo fallback)
            db.all('SELECT * FROM scans WHERE user_id = ? AND LOWER(repo_name) = LOWER(?) ORDER BY line DESC', [userId, repo], (errScans, rows) => {
                if (errScans) {
                    console.error('DB error fetching scans:', errScans);
                    return res.status(500).json({ error: 'DB Error' });
                }
                res.json({ scans: rows, mode: 'live' });
            });
        } else {
            // Not user repository: fallback to demo scans (user_id IS NULL)
            db.all('SELECT * FROM scans WHERE user_id IS NULL AND LOWER(repo_name) = LOWER(?) ORDER BY line DESC', [repo], (err2, demoRows) => {
                if (err2) {
                    console.error('DB error fetching demo scans:', err2);
                    return res.status(500).json({ error: 'DB Error' });
                }
                res.json({ scans: demoRows, mode: 'demo' });
            });
        }
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

        // Ensure repo is registered in user_repos so it displays on the dashboard (case-insensitive checking)
        db.get('SELECT id FROM user_repos WHERE user_id = ? AND LOWER(repo_name) = LOWER(?)', [userId, repo_name], (errRepo, repoRow) => {
            if (!repoRow && !errRepo) {
                db.run('INSERT INTO user_repos (user_id, repo_name, is_active) VALUES (?, ?, 1)', [userId, repo_name]);
            }
        });

        // Delete old scans for this repository under this user (case-insensitive matching)
        db.run('DELETE FROM scans WHERE user_id = ? AND LOWER(repo_name) = LOWER(?)', [userId, repo_name], (errDel) => {
            if (errDel) {
                console.error('DB error deleting old scans:', errDel);
                return res.status(500).json({ error: 'Failed to clear old scans.' });
            }

            // Insert new scans
            const stmt = db.prepare(`
                INSERT INTO scans (user_id, repo_name, file, line, consensus_score, vulnerability, description, status, original_code, corrected_code, commit_sha)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `);

            scans.forEach(s => {
                stmt.run(
                    userId, 
                    repo_name, 
                    s.file, 
                    s.line, 
                    s.consensus_score, 
                    s.vulnerability, 
                    s.description, 
                    s.status,
                    s.original_code || null,
                    s.corrected_code || null,
                    s.commit_sha || null
                );
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

// POST API to update finding feedback
app.post('/api/scans/:id/feedback', checkAuth, (req, res) => {
    const scanId = req.params.id;
    const { feedback } = req.body; // 'up', 'down', or null
    const userId = req.session.userId;

    if (feedback !== 'up' && feedback !== 'down' && feedback !== '' && feedback !== null) {
        return res.status(400).json({ error: 'Invalid feedback value' });
    }

    const feedbackVal = (feedback === '') ? null : feedback;

    db.run(
        'UPDATE scans SET feedback = ? WHERE id = ? AND (user_id = ? OR user_id IS NULL)', 
        [feedbackVal, scanId, userId], 
        function (err) {
            if (err) {
                console.error('DB error updating feedback:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({ success: true });
        }
    );
});

// HTTPS Request Helper
function makeHttpsRequest(url, options = {}, postData = null) {
    return new Promise((resolve, reject) => {
        const parsedUrl = new URL(url);
        const requestOptions = {
            hostname: parsedUrl.hostname,
            path: parsedUrl.pathname + parsedUrl.search,
            method: options.method || 'GET',
            headers: options.headers || {},
        };
        
        const req = https.request(requestOptions, (res) => {
            let body = '';
            res.on('data', (chunk) => body += chunk);
            res.on('end', () => {
                resolve({
                    statusCode: res.statusCode,
                    headers: res.headers,
                    data: body
                });
            });
        });
        
        req.on('error', (err) => reject(err));
        
        if (postData) {
            req.write(postData);
        }
        req.end();
    });
}

// POST API to approve and commit remediation patch to GitLab
app.post('/api/scans/:id/approve', checkAuth, async (req, res) => {
    const scanId = req.params.id;
    const userId = req.session.userId;

    db.get('SELECT * FROM scans WHERE id = ? AND (user_id = ? OR user_id IS NULL)', [scanId, userId], async (err, scan) => {
        if (err || !scan) {
            console.error('Scan finding not found:', err);
            return res.status(404).json({ error: 'Scan finding not found.' });
        }

        if (scan.status !== 'Pending Approval') {
            return res.status(400).json({ error: 'This finding is not pending approval.' });
        }

        db.get('SELECT gitlab_token FROM users WHERE id = ?', [userId], async (errUser, user) => {
            let gitlabToken = null;
            if (user && user.gitlab_token) {
                gitlabToken = decrypt(user.gitlab_token);
            }
            if (!gitlabToken) {
                gitlabToken = process.env.GITLAB_TOKEN;
            }

            if (!gitlabToken) {
                console.error('Server GITLAB_TOKEN is not configured.');
                return res.status(500).json({ error: 'Server is missing GitLab token configuration.' });
            }

            const projectId = encodeURIComponent(scan.repo_name);
            const fileSlug = scan.file.replace(/[^a-zA-Z0-9]/g, '_');
            const branchName = scan.commit_sha || `guardian/remediate-${fileSlug}_${scan.line}`;
            const filePathEncoded = encodeURIComponent(scan.file);

            try {
                // 1. Fetch raw file content from GitLab branch
                const fetchUrl = `https://gitlab.com/api/v4/projects/${projectId}/repository/files/${filePathEncoded}/raw?ref=${branchName}`;
                const fetchRes = await makeHttpsRequest(fetchUrl, {
                    headers: { 'PRIVATE-TOKEN': gitlabToken }
                });

                if (fetchRes.statusCode !== 200) {
                    console.error(`Failed to fetch file from GitLab. Status: ${fetchRes.statusCode}, Data: ${fetchRes.data}`);
                    return res.status(fetchRes.statusCode).json({ error: 'Failed to fetch file content from GitLab branch.' });
                }

                const currentContent = fetchRes.data;
                const originalClean = (scan.original_code || '').replace(/\r\n/g, '\n');
                const correctedClean = (scan.corrected_code || '').replace(/\r\n/g, '\n');

                if (!currentContent.replace(/\r\n/g, '\n').includes(originalClean)) {
                    return res.status(409).json({ error: 'Vulnerable code block not found in current file content. The file may have changed.' });
                }

                // Replace original with corrected in content
                const updatedContent = currentContent.replace(originalClean, correctedClean);

                // 2. Commit the changes back to GitLab Commits API
                const commitUrl = `https://gitlab.com/api/v4/projects/${projectId}/repository/commits`;
                const commitPayload = JSON.stringify({
                    branch: branchName,
                    commit_message: `fix(security): remediate ${scan.vulnerability} at line ${scan.line} [skip ci]`,
                    actions: [
                        {
                            action: 'update',
                            file_path: scan.file,
                            content: updatedContent
                        }
                    ]
                });

                const commitRes = await makeHttpsRequest(commitUrl, {
                    method: 'POST',
                    headers: {
                        'PRIVATE-TOKEN': gitlabToken,
                        'Content-Type': 'application/json',
                        'Content-Length': Buffer.byteLength(commitPayload)
                    }
                }, commitPayload);

                if (commitRes.statusCode !== 201) {
                    console.error(`Failed to commit changes. Status: ${commitRes.statusCode}, Data: ${commitRes.data}`);
                    return res.status(commitRes.statusCode).json({ error: 'Failed to commit security patch back to GitLab.' });
                }

                const commitData = JSON.parse(commitRes.data);
                const commitSha = commitData.id;

                // 3. Update status in database
                db.run(
                    'UPDATE scans SET status = ?, commit_sha = ? WHERE id = ?',
                    ['✅ Patched & Approved via Console', commitSha, scanId],
                    (errUp) => {
                        if (errUp) {
                            console.error('Failed to update scan status in DB:', errUp);
                            return res.status(500).json({ error: 'Failed to update scan status in database.' });
                        }
                        res.json({ success: true, commit_sha: commitSha });
                    }
                );

            } catch (ex) {
                console.error('Exception during approval execution:', ex);
                res.status(500).json({ error: 'Internal Server Error during patch approval.' });
            }
        });
    });
});

// POST API to reject proposed remediation patch
app.post('/api/scans/:id/reject', checkAuth, (req, res) => {
    const scanId = req.params.id;
    const userId = req.session.userId;

    db.run(
        "UPDATE scans SET status = '❌ Rejected by User' WHERE id = ? AND (user_id = ? OR user_id IS NULL)",
        [scanId, userId],
        function (err) {
            if (err) {
                console.error('Failed to reject scan finding:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({ success: true });
        }
    );
});

// POST API to trigger a manual scan in the background
app.post('/api/scans/trigger', (req, res) => {
    const { repo_name, mr_iid, guardian_user_id } = req.body;

    if (!repo_name || !mr_iid) {
        return res.status(400).json({ error: 'Missing repo_name or mr_iid.' });
    }

    // Authenticate: either via session (UI) or guardian_user_id (GitLab CI)
    let query, params;
    if (req.session && req.session.userId) {
        query = 'SELECT * FROM users WHERE id = ?';
        params = [req.session.userId];
    } else if (guardian_user_id) {
        query = 'SELECT * FROM users WHERE guardian_user_id = ?';
        params = [guardian_user_id];
    } else {
        return res.status(401).json({ error: 'Unauthorized. Missing session or guardian_user_id.' });
    }

    db.get(query, params, (err, user) => {
        if (err || !user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        // Ensure repo is registered in user_repos so it displays on the dashboard (case-insensitive checking)
        const userId = user.id;
        db.get('SELECT id FROM user_repos WHERE user_id = ? AND LOWER(repo_name) = LOWER(?)', [userId, repo_name], (errRepo, repoRow) => {
            if (!repoRow && !errRepo) {
                db.run('INSERT INTO user_repos (user_id, repo_name, is_active) VALUES (?, ?, 1)', [userId, repo_name]);
            }
        });

        const gcpProjectId = process.env.GCP_PROJECT_ID;
        const gcpLocation = process.env.GCP_LOCATION || 'us-central1';
        let gitlabToken = null;
        if (user.gitlab_token) {
            gitlabToken = decrypt(user.gitlab_token);
        }
        if (!gitlabToken) {
            gitlabToken = process.env.GITLAB_TOKEN;
        }

        if (!gcpProjectId) {
            return res.status(500).json({ error: 'Server GCP_PROJECT_ID is not configured.' });
        }
        if (!gitlabToken) {
            return res.status(500).json({ error: 'Server GitLab token is not configured.' });
        }

        const mcpUrl = process.env.GUARDIAN_MCP_URL || 'http://localhost:8000';
        
        console.log(`Sending manual security scan request to MCP server: ${mcpUrl}/trigger-scan`);
        
        fetch(`${mcpUrl}/trigger-scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                project_id: repo_name,
                mr_iid: mr_iid,
                gcp_project: gcpProjectId,
                gcp_location: gcpLocation,
                token: gitlabToken,
                guardian_user_id: user.guardian_user_id
            })
        }).then(response => {
            console.log(`Manual scan trigger response: ${response.status}`);
        }).catch(err => {
            console.error(`Error triggering manual scan:`, err);
        });

        // Immediately respond that the scan has been triggered
        res.json({ success: true, message: 'Scan triggered successfully in background.' });
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
