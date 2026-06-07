const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'guardian.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to SQLite database:', err.message);
    } else {
        console.log('Connected to SQLite database: guardian.db');
    }
});

// Initialize Tables
db.serialize(() => {
    // 1. Create users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            openrouter_key TEXT,
            guardian_user_id TEXT UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Migration step for existing databases
    db.run("ALTER TABLE users ADD COLUMN guardian_user_id TEXT UNIQUE", (err) => {
        // Safe to ignore if column already exists
    });

    // 2. Create scans table for storing findings
    db.run(`
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            repo_name TEXT NOT NULL,
            file TEXT NOT NULL,
            line INTEGER NOT NULL,
            consensus_score INTEGER NOT NULL,
            vulnerability TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);

    // Helper to check if database has mock data
    db.get("SELECT COUNT(*) as count FROM scans WHERE user_id IS NULL", (err, row) => {
        if (err) {
            console.error('Error checking scans count:', err);
            return;
        }

        if (row.count === 0) {
            console.log('Inserting simulated demo scan findings...');
            // Insert mock findings for SoftHive-group/Internal-Tools
            const mockFindings = [
                {
                    repo_name: 'SoftHive-group/Internal-Tools',
                    file: 'vulnerable_service.py',
                    line: 7,
                    consensus_score: 100,
                    vulnerability: 'Hardcoded Cloud Secret',
                    description: 'Exposed AWS Access Key ID and Secret Access Key. Move credentials to environment variables.',
                    status: '✅ Patched & Applied'
                },
                {
                    repo_name: 'SoftHive-group/Internal-Tools',
                    file: 'vulnerable_service.py',
                    line: 20,
                    consensus_score: 100,
                    vulnerability: 'SQL Injection',
                    description: 'Unsanitized user input formatted directly into raw SQL query. Use parameterized statements.',
                    status: '✅ Patched & Applied'
                },
                {
                    repo_name: 'SoftHive-group/Internal-Tools',
                    file: 'vulnerable_service.py',
                    line: 34,
                    consensus_score: 100,
                    vulnerability: 'Command Injection',
                    description: 'Unsanitized user input run directly via subprocess with shell=True. Use argument list and shell=False.',
                    status: '✅ Patched & Applied'
                },
                {
                    repo_name: 'SoftHive-group/Internal-Tools',
                    file: 'vulnerable_service.py',
                    line: 47,
                    consensus_score: 80,
                    vulnerability: 'Unsafe Deserialization',
                    description: 'Deserizaling untrusted user input using pickle.loads. Use json.loads or safe loading protocols.',
                    status: '✅ Patched & Applied'
                },
                {
                    repo_name: 'SoftHive-group/Internal-Tools',
                    file: 'vulnerable_service.py',
                    line: 60,
                    consensus_score: 60,
                    vulnerability: 'IDOR',
                    description: 'Fetches document metadata solely by ID, skipping authorization checking on request_user_id.',
                    status: '✅ Patched & Applied'
                },
                // Mock findings for Guardian-Shield/Web-Portal
                {
                    repo_name: 'Guardian-Shield/Web-Portal',
                    file: 'routes/auth.js',
                    line: 44,
                    consensus_score: 33,
                    vulnerability: 'Weak Cryptography',
                    description: 'Hashing user passwords using md5 instead of bcrypt. Upgrade hashing to robust bcrypt algorithm.',
                    status: '✅ Patched & Applied'
                },
                {
                    repo_name: 'Guardian-Shield/Web-Portal',
                    file: 'controllers/fileUpload.js',
                    line: 105,
                    consensus_score: 40,
                    vulnerability: 'Path Traversal',
                    description: 'Accepting raw filename parameters without validating boundaries, allowing reading arbitrary files.',
                    status: '❌ Failed to apply (Original block match failed)'
                }
            ];

            const stmt = db.prepare(`
                INSERT INTO scans (user_id, repo_name, file, line, consensus_score, vulnerability, description, status)
                VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)
            `);

            mockFindings.forEach(f => {
                stmt.run(f.repo_name, f.file, f.line, f.consensus_score, f.vulnerability, f.description, f.status);
            });
            stmt.finalize();
            console.log('Simulated demo scan findings inserted successfully.');
        }
    });
});

module.exports = db;
