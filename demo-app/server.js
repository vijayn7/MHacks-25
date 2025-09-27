const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// VULNERABILITY 1: Permissive CORS with credentials
app.use(cors({
  origin: '*',
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// VULNERABILITY 2: Missing security headers (no X-Frame-Options, CSP, etc.)
// Intentionally NOT setting security headers

// Home page - vulnerable to clickjacking
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Vulnerable Demo App</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .form-group { margin: 20px 0; }
        input, button { padding: 10px; margin: 5px; }
        .vulnerable { color: red; font-weight: bold; }
      </style>
    </head>
    <body>
      <h1>Swarm Demo - Vulnerable App</h1>
      <p class="vulnerable">⚠️ This app is intentionally vulnerable for testing purposes!</p>

      <div class="form-group">
        <h3>Test Reflected XSS (Vulnerable Form)</h3>
        <form action="/search" method="GET">
          <input type="text" name="q" placeholder="Enter search term" />
          <button type="submit">Search</button>
        </form>
      </div>

      <div class="form-group">
        <h3>Test Open Redirect</h3>
        <a href="/redirect?url=https://google.com">Redirect to Google</a> |
        <a href="/redirect?url=https://evil.example.com">Redirect to Evil Site</a>
      </div>

      <div class="form-group">
        <h3>Test CORS</h3>
        <button onclick="testCORS()">Test CORS Request</button>
      </div>

      <div class="form-group">
        <h3>Test Clickjacking</h3>
        <p>This page can be embedded in an iframe (missing X-Frame-Options)</p>
        <button onclick="alert('You clicked the button!')">Click Me!</button>
      </div>

      <script>
        function testCORS() {
          fetch('/api/sensitive', {
            method: 'GET',
            credentials: 'include'
          })
          .then(r => r.json())
          .then(data => alert('CORS response: ' + JSON.stringify(data)))
          .catch(e => alert('CORS error: ' + e));
        }
      </script>
    </body>
    </html>
  `);
});

// VULNERABILITY 3: Reflected XSS - unescaped user input
app.get('/search', (req, res) => {
  const query = req.query.q || '';

  // VULNERABLE: Directly inserting user input without escaping
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Search Results</title></head>
    <body>
      <h1>Search Results</h1>
      <p>You searched for: ${query}</p>
      <p>No results found for "${query}"</p>
      <a href="/">Back to Home</a>
    </body>
    </html>
  `);
});

// VULNERABILITY 4: Open Redirect
app.get('/redirect', (req, res) => {
  const url = req.query.url;

  if (!url) {
    return res.status(400).send('Missing url parameter');
  }

  // VULNERABLE: No validation of redirect URL
  res.redirect(url);
});

// VULNERABILITY 5: Sensitive API with permissive CORS
app.get('/api/sensitive', (req, res) => {
  res.json({
    message: 'This is sensitive data',
    userToken: 'abc123-secret-token',
    adminAccess: true
  });
});

// Additional vulnerable endpoints for testing
app.get('/admin', (req, res) => {
  res.send(`
    <h1>Admin Panel</h1>
    <p>This should be protected but isn't!</p>
    <p>Session: admin-session-12345</p>
  `);
});

// Endpoint that reveals server info
app.get('/debug', (req, res) => {
  res.json({
    server: 'Express.js',
    version: process.version,
    env: process.env.NODE_ENV || 'development',
    cwd: process.cwd(),
    headers: req.headers
  });
});

// File serving without proper validation
app.get('/file', (req, res) => {
  const filename = req.query.name;
  if (filename) {
    // VULNERABLE: No path validation
    res.sendFile(filename, { root: '.' });
  } else {
    res.status(400).send('Missing filename');
  }
});

// Set insecure cookies
app.get('/login', (req, res) => {
  // VULNERABLE: Insecure cookie settings
  res.cookie('session', 'user123', {
    // Missing: httpOnly, secure, sameSite
  });
  res.cookie('admin', 'true');
  res.send('Logged in with insecure cookies');
});

app.listen(PORT, () => {
  console.log(`🚨 Vulnerable demo app running on http://localhost:${PORT}`);
  console.log('⚠️  This app is INTENTIONALLY VULNERABLE - do not use in production!');
  console.log('\nVulnerable endpoints:');
  console.log(`  - GET /              (Clickjacking, missing headers)`);
  console.log(`  - GET /search?q=     (Reflected XSS)`);
  console.log(`  - GET /redirect?url= (Open Redirect)`);
  console.log(`  - GET /api/sensitive (Permissive CORS)`);
  console.log(`  - GET /admin         (Unprotected admin)`);
  console.log(`  - GET /debug         (Info disclosure)`);
  console.log(`  - GET /file?name=    (Path traversal)`);
  console.log(`  - GET /login         (Insecure cookies)`);
});