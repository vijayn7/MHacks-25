const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const crypto = require('crypto');
const { exec } = require('child_process');
const app = express();
const PORT = process.env.PORT || 3002;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Serve static assets
app.use(express.static(path.join(__dirname, 'public')));

// VULNERABILITY 1: Permissive CORS with credentials
app.use(cors({
  origin: '*',
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// VULNERABILITY 2: Missing security headers
// Intentionally NOT setting security headers for testing

// Initialize SQLite database with vulnerable setup
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT,
    email TEXT,
    role TEXT DEFAULT 'user',
    balance REAL DEFAULT 0.0
  )`);
  
  db.run(`CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT,
    price REAL,
    description TEXT
  )`);
  
  db.run(`CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    product_id INTEGER,
    quantity INTEGER,
    total REAL
  )`);
  
  // Insert test data
  db.run(`INSERT INTO users (username, password, email, role, balance) VALUES 
    ('admin', 'admin123', 'admin@test.com', 'admin', 1000.0),
    ('user1', 'password123', 'user1@test.com', 'user', 100.0),
    ('user2', 'password456', 'user2@test.com', 'user', 50.0)`);
    
  db.run(`INSERT INTO products (name, price, description) VALUES 
    ('Laptop', 999.99, 'High-end laptop'),
    ('Phone', 699.99, 'Smartphone'),
    ('Tablet', 399.99, 'Tablet device')`);
});

// VULNERABILITY 3: Weak JWT secret
const JWT_SECRET = 'weaksecret123';

// VULNERABILITY 4: Insecure random generation
const generateToken = () => {
  return Math.random().toString(36).substring(2, 15);
};

// VULNERABILITY 5: SQL Injection endpoints
app.get('/api/users', (req, res) => {
  const userId = req.query.id;
  
  // VULNERABLE: Direct SQL injection
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  db.all(query, (err, rows) => {
    if (err) {
      res.json({ error: err.message, query: query });
    } else {
      res.json(rows);
    }
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // VULNERABLE: SQL injection in login
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  db.get(query, (err, row) => {
    if (err) {
      res.json({ error: err.message, query: query });
    } else if (row) {
      // VULNERABLE: Weak JWT token
      const token = jwt.sign({ 
        id: row.id, 
        username: row.username, 
        role: row.role 
      }, JWT_SECRET, { expiresIn: '24h' });
      
      res.json({ 
        success: true, 
        token: token,
        user: { id: row.id, username: row.username, role: row.role }
      });
    } else {
      res.json({ success: false, message: 'Invalid credentials' });
    }
  });
});

// VULNERABILITY 6: IDOR (Insecure Direct Object Reference)
app.get('/api/user/:id', (req, res) => {
  const userId = req.params.id;
  
  // VULNERABLE: No authorization check
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  db.get(query, (err, row) => {
    if (err) {
      res.json({ error: err.message });
    } else if (row) {
      res.json(row);
    } else {
      res.json({ error: 'User not found' });
    }
  });
});

// VULNERABILITY 7: Business Logic - Price Manipulation
app.post('/api/purchase', (req, res) => {
  const { productId, quantity, price } = req.body;
  
  // VULNERABLE: Client can set any price
  const total = quantity * price;
  
  db.get(`SELECT * FROM products WHERE id = ${productId}`, (err, product) => {
    if (err) {
      res.json({ error: err.message });
    } else if (product) {
      res.json({ 
        success: true, 
        product: product.name,
        quantity: quantity,
        price: price,
        total: total,
        message: 'Purchase successful (vulnerable to price manipulation)'
      });
    } else {
      res.json({ error: 'Product not found' });
    }
  });
});

// VULNERABILITY 8: Command Injection
app.get('/api/ping', (req, res) => {
  const host = req.query.host || 'localhost';
  
  // VULNERABLE: Command injection
  exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    if (error) {
      res.json({ error: error.message, stderr: stderr });
    } else {
      res.json({ output: stdout, host: host });
    }
  });
});

// VULNERABILITY 9: Path Traversal
app.get('/api/file', (req, res) => {
  const filename = req.query.name;
  
  if (filename) {
    // VULNERABLE: No path validation
    const filePath = path.join(__dirname, filename);
    fs.readFile(filePath, 'utf8', (err, data) => {
      if (err) {
        res.json({ error: err.message, path: filePath });
      } else {
        res.json({ content: data, filename: filename });
      }
    });
  } else {
    res.json({ error: 'Missing filename parameter' });
  }
});

// VULNERABILITY 10: XSS (Cross-Site Scripting)
app.get('/search', (req, res) => {
  const query = req.query.q || '';
  
  // VULNERABLE: Reflected XSS
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Search Results</title>
      <link rel="icon" type="image/png" href="/Favicon.png" />
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .result { margin: 20px 0; padding: 10px; border: 1px solid #ccc; }
        .vulnerable { color: red; font-weight: bold; }
      </style>
    </head>
    <body>
      <h1>Search Results</h1>
      <p class="vulnerable">⚠️ VULNERABLE: Reflected XSS - User input not escaped!</p>
      <p>You searched for: ${query}</p>
      <div class="result">
        <h3>Search Result 1</h3>
        <p>Content related to: ${query}</p>
      </div>
      <a href="/">Back to Home</a>
    </body>
    </html>
  `);
});

// VULNERABILITY 11: Open Redirect
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  
  if (!url) {
    return res.status(400).send('Missing url parameter');
  }
  
  // VULNERABLE: No URL validation
  res.redirect(url);
});

// VULNERABILITY 12: Information Disclosure
app.get('/api/debug', (req, res) => {
  res.json({
    server: 'Express.js',
    version: process.version,
    env: process.env.NODE_ENV || 'development',
    cwd: process.cwd(),
    headers: req.headers,
    database: 'SQLite in-memory',
    jwt_secret: JWT_SECRET, // VULNERABLE: Exposing secret
    timestamp: new Date().toISOString()
  });
});

// VULNERABILITY 13: Weak Authentication
app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body;
  
  // VULNERABLE: No password strength validation
  if (username && password && email) {
    const query = `INSERT INTO users (username, password, email) VALUES ('${username}', '${password}', '${email}')`;
    
    db.run(query, function(err) {
      if (err) {
        res.json({ error: err.message, query: query });
      } else {
        res.json({ success: true, userId: this.lastID });
      }
    });
  } else {
    res.json({ error: 'Missing required fields' });
  }
});

// VULNERABILITY 14: Session Management Issues
app.get('/api/session', (req, res) => {
  // VULNERABLE: Insecure session handling
  const sessionId = req.query.session || generateToken();
  
  res.cookie('session', sessionId, {
    // Missing: httpOnly, secure, sameSite
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  });
  
  res.json({ 
    sessionId: sessionId,
    message: 'Session created (insecure)',
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000)
  });
});

// VULNERABILITY 15: Cryptographic Issues
app.get('/api/encrypt', (req, res) => {
  const text = req.query.text || 'default text';
  
  // VULNERABLE: Weak encryption
  const algorithm = 'aes-128-ecb'; // Weak algorithm
  const key = '1234567890123456'; // Weak key
  const cipher = crypto.createCipher(algorithm, key);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  res.json({ 
    original: text,
    encrypted: encrypted,
    algorithm: algorithm,
    key: key, // VULNERABLE: Exposing key
    message: 'Weak encryption used'
  });
});

// VULNERABILITY 16: Race Condition
let balance = 1000;
app.post('/api/withdraw', (req, res) => {
  const amount = parseFloat(req.body.amount) || 0;
  
  // VULNERABLE: Race condition - no locking
  if (balance >= amount) {
    setTimeout(() => {
      balance -= amount;
      res.json({ 
        success: true, 
        amount: amount, 
        newBalance: balance,
        message: 'Withdrawal successful (race condition possible)'
      });
    }, 100); // Simulate processing delay
  } else {
    res.json({ 
      success: false, 
      message: 'Insufficient funds',
      currentBalance: balance
    });
  }
});

// VULNERABILITY 17: Admin Panel without proper auth
app.get('/admin', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Panel</title>
      <link rel="icon" type="image/png" href="/Favicon.png" />
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .admin { color: red; font-weight: bold; }
        .vulnerable { color: orange; }
      </style>
    </head>
    <body>
      <h1 class="admin">🔓 Admin Panel</h1>
      <p class="vulnerable">⚠️ VULNERABLE: No authentication required!</p>
      <h2>User Management</h2>
      <p>Total Users: 3</p>
      <p>Admin Users: 1</p>
      <h2>System Information</h2>
      <p>Database: SQLite (in-memory)</p>
      <p>JWT Secret: ${JWT_SECRET}</p>
      <p>Server Time: ${new Date().toISOString()}</p>
      <a href="/">Back to Home</a>
    </body>
    </html>
  `);
});

// Main vulnerable page
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Dynamic Scanner Test App</title>
      <link rel="icon" type="image/png" href="/Favicon.png" />
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .vulnerable { color: red; font-weight: bold; background: #ffe6e6; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .form-group { margin: 15px 0; }
        input, button, select { padding: 8px; margin: 5px; border: 1px solid #ccc; border-radius: 3px; }
        button { background: #007bff; color: white; cursor: pointer; }
        button:hover { background: #0056b3; }
        .endpoint { background: #f8f9fa; padding: 10px; margin: 5px 0; border-left: 4px solid #007bff; }
        .critical { border-left-color: #dc3545; }
        .high { border-left-color: #fd7e14; }
        .medium { border-left-color: #ffc107; }
        .low { border-left-color: #28a745; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🔍 Dynamic Scanner Test Application</h1>
        <p class="vulnerable">⚠️ This application is INTENTIONALLY VULNERABLE for testing the Dynamic Scanner!</p>
        
        <div class="section">
          <h2>🎯 Test Categories</h2>
          <p>This app contains vulnerabilities across all major attack categories:</p>
          
          <div class="endpoint critical">
            <strong>SQL Injection:</strong> /api/users?id=1, /api/login, /api/user/:id
          </div>
          <div class="endpoint critical">
            <strong>XSS (Cross-Site Scripting):</strong> /search?q=&lt;script&gt;alert('XSS')&lt;/script&gt;
          </div>
          <div class="endpoint high">
            <strong>IDOR (Insecure Direct Object Reference):</strong> /api/user/1, /api/user/2
          </div>
          <div class="endpoint high">
            <strong>Command Injection:</strong> /api/ping?host=localhost;ls
          </div>
          <div class="endpoint high">
            <strong>Path Traversal:</strong> /api/file?name=../../../etc/passwd
          </div>
          <div class="endpoint medium">
            <strong>Business Logic:</strong> /api/purchase (price manipulation)
          </div>
          <div class="endpoint medium">
            <strong>Weak Authentication:</strong> /api/register, /api/login
          </div>
          <div class="endpoint medium">
            <strong>Information Disclosure:</strong> /api/debug
          </div>
          <div class="endpoint low">
            <strong>Open Redirect:</strong> /redirect?url=https://evil.com
          </div>
          <div class="endpoint low">
            <strong>Session Management:</strong> /api/session
          </div>
        </div>

        <div class="section">
          <h2>🧪 Quick Tests</h2>
          
          <div class="form-group">
            <h3>SQL Injection Test</h3>
            <input type="text" id="userId" placeholder="User ID" value="1 OR 1=1">
            <button onclick="testSQLInjection()">Test SQL Injection</button>
            <div id="sqlResult"></div>
          </div>

          <div class="form-group">
            <h3>XSS Test</h3>
            <input type="text" id="xssPayload" placeholder="XSS Payload" value="<script>alert('XSS')</script>">
            <button onclick="testXSS()">Test XSS</button>
          </div>

          <div class="form-group">
            <h3>Command Injection Test</h3>
            <input type="text" id="cmdPayload" placeholder="Command" value="localhost;ls">
            <button onclick="testCommandInjection()">Test Command Injection</button>
            <div id="cmdResult"></div>
          </div>

          <div class="form-group">
            <h3>Path Traversal Test</h3>
            <input type="text" id="pathPayload" placeholder="File path" value="../../../etc/passwd">
            <button onclick="testPathTraversal()">Test Path Traversal</button>
            <div id="pathResult"></div>
          </div>
        </div>

        <div class="section">
          <h2>🔗 Direct Links</h2>
          <p><a href="/admin" target="_blank">Admin Panel (No Auth Required)</a></p>
          <p><a href="/api/debug" target="_blank">Debug Information</a></p>
          <p><a href="/search?q=test" target="_blank">Search (XSS Vulnerable)</a></p>
          <p><a href="/redirect?url=https://google.com" target="_blank">Open Redirect</a></p>
        </div>
      </div>

      <script>
        function testSQLInjection() {
          const userId = document.getElementById('userId').value;
          fetch(\`/api/users?id=\${userId}\`)
            .then(r => r.json())
            .then(data => {
              document.getElementById('sqlResult').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            })
            .catch(e => {
              document.getElementById('sqlResult').innerHTML = '<p style="color: red;">Error: ' + e.message + '</p>';
            });
        }

        function testXSS() {
          const payload = document.getElementById('xssPayload').value;
          window.open(\`/search?q=\${encodeURIComponent(payload)}\`, '_blank');
        }

        function testCommandInjection() {
          const payload = document.getElementById('cmdPayload').value;
          fetch(\`/api/ping?host=\${encodeURIComponent(payload)}\`)
            .then(r => r.json())
            .then(data => {
              document.getElementById('cmdResult').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            })
            .catch(e => {
              document.getElementById('cmdResult').innerHTML = '<p style="color: red;">Error: ' + e.message + '</p>';
            });
        }

        function testPathTraversal() {
          const payload = document.getElementById('pathPayload').value;
          fetch(\`/api/file?name=\${encodeURIComponent(payload)}\`)
            .then(r => r.json())
            .then(data => {
              document.getElementById('pathResult').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            })
            .catch(e => {
              document.getElementById('pathResult').innerHTML = '<p style="color: red;">Error: ' + e.message + '</p>';
            });
        }
      </script>
    </body>
    </html>
  `);
});

app.listen(PORT, () => {
  console.log(`🔍 Dynamic Scanner Test App running on http://localhost:${PORT}`);
  console.log('⚠️  This app is INTENTIONALLY VULNERABLE for testing!');
  console.log('\nVulnerable endpoints:');
  console.log(`  - GET /              (Main test page)`);
  console.log(`  - GET /api/users?id= (SQL Injection)`);
  console.log(`  - POST /api/login    (SQL Injection + Weak Auth)`);
  console.log(`  - GET /api/user/:id  (IDOR)`);
  console.log(`  - GET /search?q=     (XSS)`);
  console.log(`  - GET /api/ping?host= (Command Injection)`);
  console.log(`  - GET /api/file?name= (Path Traversal)`);
  console.log(`  - POST /api/purchase (Business Logic)`);
  console.log(`  - GET /api/debug     (Information Disclosure)`);
  console.log(`  - GET /admin         (No Auth Required)`);
  console.log(`  - GET /redirect?url= (Open Redirect)`);
  console.log(`  - POST /api/register (Weak Auth)`);
  console.log(`  - GET /api/session   (Session Issues)`);
  console.log(`  - GET /api/encrypt   (Crypto Issues)`);
  console.log(`  - POST /api/withdraw (Race Condition)`);
});
