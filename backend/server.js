const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5001;

// Middleware
app.use(cors());
app.use(express.json());

// Database connection
const pool = new Pool({
  user: 'admin',
  host: 'db',
  database: 'keypouch',
  password: 'admin',
  port: 5432,
});

// JWT Secret
const JWT_SECRET = 'your-secret-key-change-in-production';

// Load RSA keys for RS256 signing (for sharing)
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

let RS_PRIVATE_KEY, RS_PUBLIC_KEY;
try {
  RS_PRIVATE_KEY = fs.readFileSync(path.join(__dirname, 'private.key'), 'utf8');
  RS_PUBLIC_KEY = fs.readFileSync(path.join(__dirname, 'public.key'), 'utf8');
  console.log('RSA keys loaded successfully for secure sharing');
} catch (error) {
  console.warn('Warning: RSA keys not found. Secure sharing will use fallback (not recommended for production).');
  // Fallback or handle error
}

const getClientIp = (req) => {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || req.ip || 'unknown';
};

const logActivity = async (username, action, details, req) => {
  try {
    const transactionId = crypto.randomBytes(16).toString('hex');
    const ip = req ? getClientIp(req) : '127.0.0.1';
    const userAgent = req ? req.headers['user-agent'] : 'Internal System';

    // Attempt to get user_id if possible
    let userId = null;
    if (req && req.user && req.user.id) {
      userId = req.user.id;
    }

    // Hash chain implementation for immutability
    const prevLogResult = await pool.query('SELECT log_hash FROM audit_logs ORDER BY id DESC LIMIT 1');
    const previousLogHash = prevLogResult.rows.length > 0 ? prevLogResult.rows[0].log_hash : '0'.repeat(64);

    const detailsStr = typeof details === 'object' ? JSON.stringify(details) : String(details || '');

    const logData = {
      username,
      userId,
      action,
      details: detailsStr,
      ip,
      userAgent,
      transactionId,
      previousLogHash,
      timestamp: new Date().toISOString()
    };

    const logHash = crypto.createHash('sha256').update(JSON.stringify(logData)).digest('hex');

    await pool.query(
      `INSERT INTO audit_logs (
        username, user_id, action, details, ip, user_agent, transaction_id, status, resource_type, timestamp, log_hash, previous_log_hash
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10, $11)`,
      [
        username,
        userId,
        action,
        detailsStr,
        ip,
        userAgent,
        transactionId,
        'success',
        details?.resourceType || 'system',
        logHash,
        previousLogHash
      ]
    );
  } catch (error) {
    console.error('Audit log error:', error);
  }
};

// Middleware to verify JWT token
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query(
      'SELECT id, username, role, is_disabled, session_version FROM users WHERE id = $1',
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const dbUser = result.rows[0];
    const tokenVersion = decoded.sv ?? 0;

    if (dbUser.is_disabled) {
      return res.status(403).json({ error: 'Account disabled' });
    }

    if (dbUser.session_version !== tokenVersion) {
      return res.status(401).json({ error: 'Session expired' });
    }

    req.user = {
      userId: dbUser.id,
      id: dbUser.id,
      username: dbUser.username,
      role: dbUser.role || 'view'
    };
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Forbidden' });
  }
};

// Database connection retry logic
const connectWithRetry = () => {
  console.log('Attempting to connect to database...');
  pool.query('SELECT NOW()', (err, res) => {
    if (err) {
      console.error('Database connection error:', err.message);
      console.log('Retrying in 5 seconds...');
      setTimeout(connectWithRetry, 5000);
    } else {
      console.log('Database connected successfully at:', res.rows[0].now);
    }
  });
};

connectWithRetry();

// Role-based permission middleware
const checkPermission = (requiredRole) => {
  return (req, res, next) => {
    const userRole = req.user.role;

    const roleHierarchy = {
      'view': 1,
      'modify': 2,
      'full-access': 3,
      'admin': 4
    };

    const userLevel = roleHierarchy[userRole] || 0;
    const requiredLevel = roleHierarchy[requiredRole] || 0;

    if (userLevel < requiredLevel) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
};

const isValidEmail = (email) => typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const isValidPhone = (phone) => typeof phone === 'string' && /^[0-9+().\-\s]{7,20}$/.test(phone);
const isValidTransport = (transport) => ['udp', 'tcp', 'tls', 'wss'].includes(transport);

// Auth Routes
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query(
      'SELECT id, username, password, role, is_disabled, session_version, must_reset_password, is_demo FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      await logActivity(username || 'unknown', 'LOGIN_FAILED', 'Failed login attempt', req);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    if (user.is_disabled) {
      await logActivity(user.username, 'LOGIN_BLOCKED', 'Login blocked: account disabled', req);
      return res.status(403).json({ error: 'Account disabled' });
    }

    // Simple password comparison (since we stored plain text for now)
    if (password !== user.password) {
      await logActivity(username || 'unknown', 'LOGIN_FAILED', 'Failed login attempt', req);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await pool.query('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
    await logActivity(user.username, 'LOGIN', 'User logged in successfully', req);

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role || 'view', sv: user.session_version || 0 },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      username: user.username,
      role: user.role || 'view',
      must_reset_password: user.must_reset_password || false,
      is_demo: user.is_demo || false
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Security Question / Password Reset (Public)
app.get('/api/auth/security-question', async (req, res) => {
  try {
    const username = typeof req.query.username === 'string' ? req.query.username : '';
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    const result = await pool.query(
      'SELECT security_question FROM users WHERE username = $1',
      [username]
    );
    if (result.rows.length === 0 || !result.rows[0].security_question) {
      return res.status(404).json({ error: 'User not found or no security question set' });
    }

    res.json({ question: result.rows[0].security_question });
  } catch (error) {
    console.error('Get security question error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/verify-security-answer', async (req, res) => {
  try {
    const { username, answer } = req.body;
    if (!username || !answer) {
      return res.status(400).json({ error: 'Username and answer are required' });
    }

    const result = await pool.query(
      'SELECT id, username, security_answer FROM users WHERE username = $1',
      [username]
    );
    if (result.rows.length === 0 || !result.rows[0].security_answer) {
      return res.status(404).json({ error: 'User not found or no security answer set' });
    }

    const expected = String(result.rows[0].security_answer).trim().toLowerCase();
    const provided = String(answer).trim().toLowerCase();
    if (expected !== provided) {
      await logActivity(username, 'SECURITY_FAIL', 'Security question check failed', req);
      return res.status(403).json({ error: 'Incorrect answer' });
    }

    const token = jwt.sign(
      { typ: 'pwd_reset', id: result.rows[0].id, username: result.rows[0].username },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    await logActivity(username, 'SECURITY_VERIFY', 'Security question verified', req);
    res.json({ message: 'Answer verified', token });
  } catch (error) {
    console.error('Verify security answer error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and newPassword are required' });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    if (!decoded || typeof decoded !== 'object' || decoded.typ !== 'pwd_reset' || !decoded.id) {
      return res.status(400).json({ error: 'Invalid reset token' });
    }

    const result = await pool.query(
      'UPDATE users SET password = $1, must_reset_password = FALSE, password_changed_at = CURRENT_TIMESTAMP, session_version = session_version + 1 WHERE id = $2 RETURNING username',
      [newPassword, decoded.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    await logActivity(result.rows[0].username, 'PASSWORD_RESET', 'Password successfully reset', req);
    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Change password for the currently authenticated user (supports forced reset)
app.post('/api/me/change-password', authenticateToken, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!new_password) {
      return res.status(400).json({ error: 'new_password is required' });
    }

    const current = await pool.query(
      'SELECT id, username, password, role, must_reset_password, session_version FROM users WHERE id = $1',
      [req.user.id]
    );
    if (current.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const u = current.rows[0];
    if (!u.must_reset_password) {
      if (!current_password) {
        return res.status(400).json({ error: 'current_password is required' });
      }
      if (String(current_password) !== String(u.password)) {
        return res.status(403).json({ error: 'Current password is incorrect' });
      }
    }

    const updated = await pool.query(
      'UPDATE users SET password = $1, must_reset_password = FALSE, password_changed_at = CURRENT_TIMESTAMP, session_version = session_version + 1 WHERE id = $2 RETURNING id, username, role, session_version',
      [new_password, u.id]
    );
    const next = updated.rows[0];

    await logActivity(next.username, 'PASSWORD_CHANGE', 'User changed password', req);

    const nextToken = jwt.sign(
      { id: next.id, username: next.username, role: next.role || 'view', sv: next.session_version || 0 },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ message: 'Password updated', token: nextToken });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, password, securityQuestion, securityAnswer } = req.body;

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Insert new user
    const result = await pool.query(
      'INSERT INTO users (username, password, role, security_question, security_answer, password_changed_at) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP) RETURNING id, username, role, session_version',
      [username, password, 'view', securityQuestion || null, securityAnswer || null]
    );

    const newUser = result.rows[0];

    const token = jwt.sign(
      { id: newUser.id, username: newUser.username, role: newUser.role, sv: newUser.session_version || 0 },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    await logActivity(newUser.username, 'REGISTER', 'User registered', req);

    res.json({
      message: 'Registration successful',
      token,
      username: newUser.username,
      role: newUser.role
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Customer Admin Registration (Public endpoint for first-time setup)
app.post('/api/register-admin', async (req, res) => {
  try {
    const { username, password, securityQuestion, securityAnswer, companyName } = req.body;

    // Check if any real admin already exists
    const existingAdmin = await pool.query(
      'SELECT id FROM users WHERE role = $1 AND is_demo = FALSE',
      ['admin']
    );

    if (existingAdmin.rows.length > 0) {
      return res.status(403).json({ error: 'Admin user already exists. Contact support for admin access.' });
    }

    // Check if username already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Insert new real admin user
    const result = await pool.query(
      'INSERT INTO users (username, password, role, security_question, security_answer, is_demo, password_changed_at) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP) RETURNING id, username, role, session_version, is_demo',
      [username, password, 'admin', securityQuestion || null, securityAnswer || null, false]
    );

    const newAdmin = result.rows[0];

    // Disable demo accounts after real admin creation (keeps the demo users for development, but prevents use in customer setups).
    await pool.query(
      'UPDATE users SET is_disabled = TRUE, session_version = session_version + 1 WHERE is_demo = TRUE'
    );
    await logActivity(newAdmin.username, 'DEMO_DISABLED', 'Disabled demo accounts after real admin setup', req);

    const token = jwt.sign(
      { id: newAdmin.id, username: newAdmin.username, role: newAdmin.role, sv: newAdmin.session_version || 0 },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    await logActivity(newAdmin.username, 'ADMIN_REGISTER', `Real admin user registered for company: ${companyName || 'N/A'}`, req);

    res.json({
      message: 'Admin registration successful',
      token,
      username: newAdmin.username,
      role: newAdmin.role,
      is_demo: newAdmin.is_demo
    });
  } catch (error) {
    console.error('Admin registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User Management Routes (Admin Only)
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const result = await pool.query(
      'SELECT id, username, role, created_at, is_disabled, must_reset_password, mfa_enabled, last_login_at, is_demo FROM users ORDER BY created_at'
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { id } = req.params;
    const { role } = req.body;

    if (!role) {
      return res.status(400).json({ error: 'Role is required' });
    }

    const result = await pool.query(
      'UPDATE users SET role = $1 WHERE id = $2 RETURNING id, username, role, is_disabled, must_reset_password, mfa_enabled, last_login_at, created_at',
      [role, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    await logActivity(req.user.username, 'USER_UPDATE', `Changed role for ${result.rows[0].username} to ${role}`, req);

    res.json({ message: 'User updated', user: result.rows[0] });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Partial user update (Admin Only) - for editing permissions/status from the admin panel
app.patch('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { id } = req.params;
    const { role, is_disabled, must_reset_password } = req.body;

    if (role === undefined && is_disabled === undefined && must_reset_password === undefined) {
      return res.status(400).json({ error: 'No fields provided to update' });
    }

    const existing = await pool.query(
      'SELECT role, is_disabled, must_reset_password FROM users WHERE id = $1',
      [id]
    );
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const current = existing.rows[0];
    const nextRole = role !== undefined ? role : current.role;
    const nextDisabled = is_disabled !== undefined ? !!is_disabled : current.is_disabled;
    const nextMustReset = must_reset_password !== undefined ? !!must_reset_password : current.must_reset_password;

    const bumpSessions =
      (is_disabled !== undefined && nextDisabled !== current.is_disabled) ||
        (must_reset_password !== undefined && nextMustReset !== current.must_reset_password)
        ? 1
        : 0;

    const result = await pool.query(
      'UPDATE users SET role = $1, is_disabled = $2, must_reset_password = $3, session_version = session_version + $4 WHERE id = $5 RETURNING id, username, role, is_disabled, must_reset_password, mfa_enabled, last_login_at, created_at',
      [nextRole, nextDisabled, nextMustReset, bumpSessions, id]
    );

    await logActivity(
      req.user.username,
      'USER_UPDATE',
      `Patched user ${result.rows[0].username}: role=${nextRole}, disabled=${nextDisabled}, reset_password=${nextMustReset}${bumpSessions ? ' (sessions revoked)' : ''}`,
      req
    );

    res.json({ message: 'User updated', user: result.rows[0] });
  } catch (error) {
    console.error('Patch user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/users', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { username, password, role, is_disabled, must_reset_password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const existingUser = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const safeRole = role || 'view';
    const result = await pool.query(
      'INSERT INTO users (username, password, role, is_disabled, must_reset_password, password_changed_at) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP) RETURNING id, username, role, created_at, is_disabled, must_reset_password, mfa_enabled, last_login_at',
      [username, password, safeRole, !!is_disabled, !!must_reset_password]
    );

    await logActivity(req.user.username, 'USER_CREATE', `Created user: ${username}`, req);

    res.status(201).json({ message: 'User created', user: result.rows[0] });
  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { id } = req.params;
    const result = await pool.query(
      'SELECT id, username, role, created_at, is_disabled, must_reset_password, mfa_enabled, last_login_at, password_changed_at, security_question FROM users WHERE id = $1',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get user detail error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/users/:id/audit-logs', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { id } = req.params;
    const userResult = await pool.query('SELECT username FROM users WHERE id = $1', [id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const username = userResult.rows[0].username;
    const logs = await pool.query(
      'SELECT * FROM audit_logs WHERE username = $1 ORDER BY timestamp DESC LIMIT 200',
      [username]
    );

    res.json(logs.rows);
  } catch (error) {
    console.error('Get user audit logs error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/users/:id/status', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { id } = req.params;
    const { is_disabled } = req.body;

    const result = await pool.query(
      'UPDATE users SET is_disabled = $1, session_version = session_version + 1 WHERE id = $2 RETURNING id, username, role, created_at, is_disabled, must_reset_password, mfa_enabled, last_login_at',
      [!!is_disabled, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    await logActivity(req.user.username, 'USER_STATUS', `Set ${result.rows[0].username} disabled=${!!is_disabled}`, req);
    res.json({ message: 'User status updated', user: result.rows[0] });
  } catch (error) {
    console.error('Update user status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/users/:id/reset-password', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { id } = req.params;
    const { new_password } = req.body;
    if (!new_password) {
      return res.status(400).json({ error: 'New password is required' });
    }

    const result = await pool.query(
      'UPDATE users SET password = $1, must_reset_password = TRUE, password_changed_at = CURRENT_TIMESTAMP, session_version = session_version + 1 WHERE id = $2 RETURNING id, username',
      [new_password, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    await logActivity(req.user.username, 'PASSWORD_RESET_ADMIN', `Admin reset password for ${result.rows[0].username}`, req);
    res.json({ message: 'Password reset', user: result.rows[0] });
  } catch (error) {
    console.error('Admin reset password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/users/:id/revoke-sessions', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { id } = req.params;
    const result = await pool.query(
      'UPDATE users SET session_version = session_version + 1 WHERE id = $1 RETURNING id, username',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    await logActivity(req.user.username, 'SESSIONS_REVOKED', `Revoked sessions for ${result.rows[0].username}`, req);
    res.json({ message: 'Sessions revoked', user: result.rows[0] });
  } catch (error) {
    console.error('Revoke sessions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/users/:id/reset-mfa', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { id } = req.params;
    const result = await pool.query(
      'UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL WHERE id = $1 RETURNING id, username',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    await logActivity(req.user.username, 'MFA_RESET', `Reset MFA for ${result.rows[0].username}`, req);
    res.json({ message: 'MFA reset', user: result.rows[0] });
  } catch (error) {
    console.error('Reset MFA error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { id } = req.params;

    const result = await pool.query('DELETE FROM users WHERE id = $1', [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    await logActivity(req.user.username, 'USER_DELETE', `Deleted user ID: ${id}`, req);
    res.json({ message: 'User deleted' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Contacts Routes
app.get('/api/contacts', authenticateToken, checkPermission('view'), async (req, res) => {
  try {
    const { search } = req.query;
    let query = 'SELECT * FROM contacts WHERE user_id = $1 ORDER BY created_at DESC';
    let params = [req.user.id];

    if (search) {
      query = 'SELECT * FROM contacts WHERE user_id = $1 AND (name ILIKE $2 OR phone ILIKE $2 OR address ILIKE $2) ORDER BY created_at DESC';
      params = [req.user.id, `%${search}%`];
    }

    const result = await pool.query(query, params);
    const contacts = result.rows;
    if (!contacts.length) {
      return res.json([]);
    }

    const contactIds = contacts.map(contact => contact.id);
    const emergencyResult = await pool.query(
      'SELECT * FROM emergency_contacts WHERE contact_id = ANY($1::int[]) ORDER BY created_at ASC',
      [contactIds]
    );

    const emergencyByContact = emergencyResult.rows.reduce((acc, row) => {
      if (!acc[row.contact_id]) acc[row.contact_id] = [];
      acc[row.contact_id].push(row);
      return acc;
    }, {});

    const withEmergencyContacts = contacts.map(contact => ({
      ...contact,
      emergencyContacts: emergencyByContact[contact.id] || []
    }));

    res.json(withEmergencyContacts);
  } catch (error) {
    console.error('Get contacts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/contacts/export', authenticateToken, checkPermission('view'), async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM contacts WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    const contacts = result.rows;

    // Fetch emergency contacts
    if (contacts.length === 0) {
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="contacts_${new Date().toISOString().split('T')[0]}.csv"`);
      res.send('name,phone,address,emergency_contacts\n');
      return;
    }

    const contactIds = contacts.map(contact => contact.id);
    const emergencyResult = await pool.query(
      'SELECT * FROM emergency_contacts WHERE contact_id = ANY($1::int[]) ORDER BY created_at ASC',
      [contactIds]
    );

    const emergencyByContact = emergencyResult.rows.reduce((acc, row) => {
      if (!acc[row.contact_id]) acc[row.contact_id] = [];
      acc[row.contact_id].push(row);
      return acc;
    }, {});

    // Build CSV
    const csvHeader = 'name,phone,address,emergency_contacts\n';
    const csvRows = contacts.map(contact => {
      const emergency = emergencyByContact[contact.id] || [];
      const emergencyJson = JSON.stringify(emergency.map(e => ({
        name: e.name,
        phone: e.phone,
        email: e.email,
        relationship: e.relationship
      })));
      const escapedEmergency = `"${emergencyJson.replace(/"/g, '""')}"`;
      const escapedName = `"${(contact.name || '').replace(/"/g, '""')}"`;
      const escapedPhone = `"${(contact.phone || '').replace(/"/g, '""')}"`;
      const escapedAddress = `"${(contact.address || '').replace(/"/g, '""')}"`;
      return `${escapedName},${escapedPhone},${escapedAddress},${escapedEmergency}`;
    }).join('\n');

    const csv = csvHeader + csvRows;

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="contacts_${new Date().toISOString().split('T')[0]}.csv"`);
    res.send(csv);
  } catch (error) {
    console.error('Export contacts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/contacts', authenticateToken, checkPermission('modify'), async (req, res) => {
  try {
    const { name, phone, address } = req.body;

    const result = await pool.query(
      'INSERT INTO contacts (user_id, name, phone, address) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.user.id, name, phone, address]
    );

    res.status(201).json({
      message: 'Contact created',
      contact: result.rows[0]
    });
  } catch (error) {
    console.error('Create contact error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/contacts/:id', authenticateToken, checkPermission('modify'), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, phone, address } = req.body;

    const result = await pool.query(
      'UPDATE contacts SET name = $1, phone = $2, address = $3 WHERE id = $4 AND user_id = $5 RETURNING *',
      [name, phone, address, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Contact not found' });
    }

    res.json({ message: 'Contact updated' });
  } catch (error) {
    console.error('Update contact error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/contacts/:id/emergency-contacts', authenticateToken, checkPermission('modify'), async (req, res) => {
  try {
    const contactId = parseInt(req.params.id);
    if (Number.isNaN(contactId)) {
      return res.status(400).json({ error: 'Invalid contact id' });
    }

    const { name, phone, email, relationship } = req.body;
    if (!name || !phone || !email || !relationship) {
      return res.status(400).json({ error: 'Name, phone, email, and relationship are required' });
    }
    if (!isValidPhone(phone)) {
      return res.status(400).json({ error: 'Invalid phone number format' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    const contactResult = await pool.query(
      'SELECT id FROM contacts WHERE id = $1 AND user_id = $2',
      [contactId, req.user.id]
    );

    if (contactResult.rows.length === 0) {
      return res.status(404).json({ error: 'Contact not found' });
    }

    const insertResult = await pool.query(
      'INSERT INTO emergency_contacts (contact_id, name, phone, email, relationship) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [contactId, name, phone, email, relationship]
    );

    res.status(201).json(insertResult.rows[0]);
  } catch (error) {
    console.error('Add emergency contact error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/contacts/:id/emergency-contacts/:emergencyId', authenticateToken, checkPermission('modify'), async (req, res) => {
  try {
    const contactId = parseInt(req.params.id);
    const emergencyId = parseInt(req.params.emergencyId);
    if (Number.isNaN(contactId) || Number.isNaN(emergencyId)) {
      return res.status(400).json({ error: 'Invalid id' });
    }

    const { name, phone, email, relationship } = req.body;
    if (!name || !phone || !email || !relationship) {
      return res.status(400).json({ error: 'Name, phone, email, and relationship are required' });
    }
    if (!isValidPhone(phone)) {
      return res.status(400).json({ error: 'Invalid phone number format' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    const updateResult = await pool.query(
      `UPDATE emergency_contacts ec
       SET name = $1, phone = $2, email = $3, relationship = $4
       FROM contacts c
       WHERE ec.id = $5 AND ec.contact_id = $6 AND c.id = ec.contact_id AND c.user_id = $7
       RETURNING ec.*`,
      [name, phone, email, relationship, emergencyId, contactId, req.user.id]
    );

    if (updateResult.rows.length === 0) {
      return res.status(404).json({ error: 'Emergency contact not found' });
    }

    res.json(updateResult.rows[0]);
  } catch (error) {
    console.error('Update emergency contact error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/contacts/:id/emergency-contacts/:emergencyId', authenticateToken, checkPermission('modify'), async (req, res) => {
  try {
    const contactId = parseInt(req.params.id);
    const emergencyId = parseInt(req.params.emergencyId);
    if (Number.isNaN(contactId) || Number.isNaN(emergencyId)) {
      return res.status(400).json({ error: 'Invalid id' });
    }

    const result = await pool.query(
      `DELETE FROM emergency_contacts ec
       USING contacts c
       WHERE ec.id = $1 AND ec.contact_id = $2 AND c.id = ec.contact_id AND c.user_id = $3`,
      [emergencyId, contactId, req.user.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Emergency contact not found' });
    }

    res.json({ message: 'Emergency contact deleted' });
  } catch (error) {
    console.error('Delete emergency contact error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/contacts/:id', authenticateToken, checkPermission('full-access'), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM contacts WHERE id = $1 AND user_id = $2',
      [id, req.user.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Contact not found' });
    }

    res.json({ message: 'Contact deleted' });
  } catch (error) {
    console.error('Delete contact error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// SIP Accounts Routes
app.get('/api/sip-accounts', authenticateToken, checkPermission('view'), async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, label, server_type, server_host, server_port, username, extension, transport, ws_path, created_at FROM sip_accounts WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get SIP accounts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/sip-accounts', authenticateToken, checkPermission('modify'), async (req, res) => {
  try {
    const { label, server_type, server_host, server_port, username, password, extension, transport, ws_path } = req.body;

    if (!server_type || !server_host || !username || !password) {
      return res.status(400).json({ error: 'Server type, host, username, and password are required' });
    }
    if (transport && !isValidTransport(transport)) {
      return res.status(400).json({ error: 'Invalid transport' });
    }

    const result = await pool.query(
      `INSERT INTO sip_accounts (user_id, label, server_type, server_host, server_port, username, password_encrypted, extension, transport, ws_path)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING id, label, server_type, server_host, server_port, username, extension, transport, ws_path, created_at`,
      [
        req.user.id,
        label || null,
        server_type,
        server_host,
        server_port || 5060,
        username,
        password,
        extension || null,
        transport || 'wss',
        ws_path || '/ws'
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Create SIP account error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/sip-accounts/:id', authenticateToken, checkPermission('modify'), async (req, res) => {
  try {
    const { id } = req.params;
    const { label, server_type, server_host, server_port, username, password, extension, transport, ws_path } = req.body;

    if (!server_type || !server_host || !username) {
      return res.status(400).json({ error: 'Server type, host, and username are required' });
    }
    if (transport && !isValidTransport(transport)) {
      return res.status(400).json({ error: 'Invalid transport' });
    }

    const result = await pool.query(
      `UPDATE sip_accounts
       SET label = $1, server_type = $2, server_host = $3, server_port = $4, username = $5,
           password_encrypted = COALESCE($6, password_encrypted), extension = $7, transport = $8, ws_path = $9
       WHERE id = $10 AND user_id = $11
       RETURNING id, label, server_type, server_host, server_port, username, extension, transport, ws_path, created_at`,
      [
        label || null,
        server_type,
        server_host,
        server_port || 5060,
        username,
        password || null,
        extension || null,
        transport || 'wss',
        ws_path || '/ws',
        id,
        req.user.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'SIP account not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Update SIP account error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/sip-accounts/:id', authenticateToken, checkPermission('modify'), async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      'DELETE FROM sip_accounts WHERE id = $1 AND user_id = $2',
      [id, req.user.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'SIP account not found' });
    }

    res.json({ message: 'SIP account deleted' });
  } catch (error) {
    console.error('Delete SIP account error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Call Logs Routes
app.post('/api/call-logs', authenticateToken, checkPermission('modify'), async (req, res) => {
  try {
    const { contact_id, sip_account_id, phone_number, direction, status, duration_seconds, started_at, ended_at } = req.body;
    if (!contact_id || !direction || !status || !started_at) {
      return res.status(400).json({ error: 'Contact, direction, status, and started_at are required' });
    }

    const contactResult = await pool.query(
      'SELECT id FROM contacts WHERE id = $1 AND user_id = $2',
      [contact_id, req.user.id]
    );
    if (contactResult.rows.length === 0) {
      return res.status(404).json({ error: 'Contact not found' });
    }

    const result = await pool.query(
      `INSERT INTO call_logs (user_id, contact_id, sip_account_id, phone_number, direction, status, duration_seconds, started_at, ended_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        req.user.id,
        contact_id,
        sip_account_id || null,
        phone_number || null,
        direction,
        status,
        duration_seconds || 0,
        started_at,
        ended_at || null
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Create call log error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/contacts/:id/call-logs', authenticateToken, checkPermission('view'), async (req, res) => {
  try {
    const { id } = req.params;
    const contactResult = await pool.query(
      'SELECT id FROM contacts WHERE id = $1 AND user_id = $2',
      [id, req.user.id]
    );
    if (contactResult.rows.length === 0) {
      return res.status(404).json({ error: 'Contact not found' });
    }

    const result = await pool.query(
      'SELECT * FROM call_logs WHERE contact_id = $1 AND user_id = $2 ORDER BY started_at DESC LIMIT 50',
      [id, req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Get call logs error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Secrets Routes
app.get('/api/secrets', authenticateToken, checkPermission('view'), async (req, res) => {
  try {
    const { search, category } = req.query;
    let query = 'SELECT * FROM secrets WHERE user_id = $1';
    let params = [req.user.id];
    let whereClause = '';

    if (search) {
      whereClause += ' AND title ILIKE $' + (params.length + 1);
      params.push(`%${search}%`);
    }

    if (category) {
      whereClause += ' AND category = $' + (params.length + 1);
      params.push(category);
    }

    query += whereClause + ' ORDER BY created_at DESC';

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Get secrets error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/secrets/:id', authenticateToken, checkPermission('view'), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'SELECT id, user_id, title, category, username, url, notes, encrypted_content, content_iv, content_auth_tag, version, encryption_algorithm, created_at, updated_at FROM secrets WHERE id = $1 AND user_id = $2 AND is_deleted = FALSE',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Secret not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get secret error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/secrets', authenticateToken, checkPermission('modify'), async (req, res) => {
  try {
    const { title, category, username, password, api_key, url, notes, encrypted_content, content_iv, content_auth_tag } = req.body;

    const result = await pool.query(
      `INSERT INTO secrets (
        user_id, title, category, username, password, api_key, url, notes, 
        encrypted_content, content_iv, content_auth_tag
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
      [
        req.user.id, title, category || 'general', username, password, api_key, url, notes,
        encrypted_content, content_iv, content_auth_tag
      ]
    );

    await logActivity(req.user.username, 'SECRET_CREATED', { secretId: result.rows[0].id, title }, req);

    res.status(201).json({ message: 'Secret created', id: result.rows[0].id });
  } catch (error) {
    console.error('Create secret error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/secrets/:id', authenticateToken, checkPermission('modify'), async (req, res) => {
  try {
    const { id } = req.params;
    const { title, category, username, password, api_key, url, notes, encrypted_content, content_iv, content_auth_tag } = req.body;

    const result = await pool.query(
      `UPDATE secrets SET 
        title = $1, category = $2, username = $3, password = $4, api_key = $5, url = $6, notes = $7, 
        encrypted_content = $8, content_iv = $9, content_auth_tag = $10,
        updated_at = CURRENT_TIMESTAMP, version = version + 1 
      WHERE id = $11 AND user_id = $12 RETURNING id`,
      [
        title, category, username, password, api_key, url, notes,
        encrypted_content, content_iv, content_auth_tag,
        id, req.user.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Secret not found' });
    }

    await logActivity(req.user.username, 'SECRET_UPDATED', { secretId: id, title }, req);

    res.json({ message: 'Secret updated' });
  } catch (error) {
    console.error('Update secret error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/secrets/:id', authenticateToken, checkPermission('full-access'), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'UPDATE secrets SET is_deleted = TRUE, deleted_at = CURRENT_TIMESTAMP WHERE id = $1 AND user_id = $2 RETURNING id, title',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Secret not found' });
    }

    await logActivity(req.user.username, 'SECRET_DELETED', { secretId: id, title: result.rows[0].title }, req);

    // Revoke all existing shares for this secret
    await pool.query(
      'UPDATE shared_secrets SET is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP WHERE secret_id = $1',
      [id]
    );

    res.json({ message: 'Secret deleted' });
  } catch (error) {
    console.error('Delete secret error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- SHARING ENDPOINTS ---

app.post('/api/secrets/:id/share', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { expiresInMinutes, maxViews = 1, allowedEmails, encrypted_content, content_iv, content_auth_tag, secretData } = req.body;
    const userId = req.user.id;

    const secretResult = await pool.query(
      'SELECT id, user_id, title FROM secrets WHERE id = $1 AND user_id = $2 AND is_deleted = FALSE',
      [id, userId]
    );

    if (secretResult.rows.length === 0) {
      return res.status(404).json({ error: 'Secret not found' });
    }

    const expiresAt = expiresInMinutes
      ? new Date(Date.now() + expiresInMinutes * 60000)
      : null;

    const sharePayload = {
      secret_id: parseInt(id),
      created_by: userId,
      created_at: new Date().toISOString(),
      expires_at: expiresAt?.toISOString() || null,
      max_views: maxViews,
      jti: crypto.randomBytes(16).toString('hex'),
    };

    const shareToken = jwt.sign(sharePayload, RS_PRIVATE_KEY, {
      algorithm: 'RS256',
    });

    // If client sent encrypted data, use it directly
    // Otherwise, server-side encrypt the data
    let finalEncryptedContent = encrypted_content;
    let finalContentIv = content_iv;
    let finalContentAuthTag = content_auth_tag;
    
    if (!encrypted_content && secretData) {
      // Server-side encryption fallback
      // Store the secret data as-is (could be encrypted on server in production)
      // For now, we'll store it as JSON for demo purposes
      finalEncryptedContent = JSON.stringify(secretData);
      console.log('[SHARE] Using server-side data storage (no client-side crypto available)');
    }
    
    await pool.query(
      `INSERT INTO shared_secrets (
        id, secret_id, created_by, max_views, expires_at, allowed_emails, created_at,
        encrypted_content, content_iv, content_auth_tag
      ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7, $8, $9)`,
      [
        sharePayload.jti,
        id,
        userId,
        maxViews,
        expiresAt,
        allowedEmails ? JSON.stringify(allowedEmails) : null,
        finalEncryptedContent,
        finalContentIv,
        finalContentAuthTag
      ]
    );

    await logActivity(req.user.username, 'SECRET_SHARED', {
      secretId: id,
      secretTitle: secretResult.rows[0].title,
      expiresAt,
      maxViews,
    }, req);

    res.status(201).json({
      token: shareToken,
      expiresAt: expiresAt?.toISOString() || null,
      maxViews,
    });
  } catch (error) {
    console.error('Create share error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/secrets/:id/audit-log', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { action, details } = req.body;

    const secretResult = await pool.query(
      'SELECT title FROM secrets WHERE id = $1 AND user_id = $2',
      [id, req.user.id]
    );

    if (secretResult.rows.length === 0) {
      return res.status(404).json({ error: 'Secret not found' });
    }

    const logDetails = {
      secretId: id,
      title: secretResult.rows[0].title,
      ...details,
      resourceType: 'secret'
    };

    await logActivity(req.user.username, `SECRET_${action.toUpperCase()}`, logDetails, req);
    res.json({ message: 'Action logged' });
  } catch (error) {
    console.error('Log secret action error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/shared-secrets/:token', async (req, res) => {
  try {
    const { token } = req.params;

    let decoded;
    try {
      decoded = jwt.verify(token, RS_PUBLIC_KEY, { algorithms: ['RS256'] });
    } catch (error) {
      return res.status(401).json({ error: 'invalid_share_token' });
    }

    const { secret_id, jti } = decoded;

    const shareResult = await pool.query(
      `SELECT id, secret_id, created_by, max_views, views_count, 
              expires_at, is_revoked, destroyed_at,
              encrypted_content, content_iv, content_auth_tag
       FROM shared_secrets WHERE id = $1`,
      [jti]
    );

    if (shareResult.rows.length === 0 || shareResult.rows[0].destroyed_at || shareResult.rows[0].is_revoked) {
      return res.status(410).json({ error: 'shared_secret_unavailable' });
    }

    const share = shareResult.rows[0];

    if (share.expires_at && new Date(share.expires_at) < new Date()) {
      return res.status(410).json({ error: 'share_expired' });
    }

    const secretResult = await pool.query(
      `SELECT id, title, category, username, url
       FROM secrets WHERE id = $1 AND is_deleted = FALSE`,
      [secret_id]
    );

    if (secretResult.rows.length === 0) {
      return res.status(404).json({ error: 'Secret not found' });
    }

    const secret = secretResult.rows[0];

    // Atomically increment views and check for destruction
    await pool.query(
      'UPDATE shared_secrets SET views_count = views_count + 1, viewed_at = NOW() WHERE id = $1',
      [jti]
    );

    if (share.max_views === 1 || (share.views_count + 1 >= share.max_views)) {
      const destructionHash = crypto.createHash('sha256')
        .update(JSON.stringify({ share_id: jti, destroyed_at: new Date().toISOString() }))
        .digest('hex');

      await pool.query(
        'UPDATE shared_secrets SET destroyed_at = NOW(), destruction_hash = $1 WHERE id = $2',
        [destructionHash, jti]
      );

      await logActivity('system', 'SHARED_SECRET_DESTROYED', {
        shareId: jti,
        secretId: secret_id,
        verificationHash: destructionHash,
      }, req);
    }

    res.json({
      title: secret.title,
      category: secret.category,
      encrypted_content: share.encrypted_content,
      content_iv: share.content_iv,
      content_auth_tag: share.content_auth_tag,
      username: secret.username,
      url: secret.url,
    });
  } catch (error) {
    console.error('Get shared secret error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/secrets/:id/shares', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      'SELECT id, max_views, views_count, expires_at, is_revoked, created_at, destroyed_at FROM shared_secrets WHERE secret_id = $1 AND created_by = $2 ORDER BY created_at DESC',
      [id, req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('List shares error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Audit Logs Route
app.get('/api/audit-logs', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const result = await pool.query(
      'SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 200'
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Get audit logs error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Custom Categories Routes
app.get('/api/custom-categories', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, label, created_at FROM custom_categories WHERE user_id = $1 ORDER BY label',
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get custom categories error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/custom-categories', authenticateToken, async (req, res) => {
  try {
    const { label } = req.body;

    if (!label || label.trim().length === 0) {
      return res.status(400).json({ error: 'Category label is required' });
    }

    const id = label.toLowerCase().replace(/[^a-z0-9]/g, '-');

    const result = await pool.query(
      'INSERT INTO custom_categories (id, label, user_id) VALUES ($1, $2, $3) RETURNING id, label, created_at',
      [id, label.trim(), req.user.userId]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Create custom category error:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'Category already exists' });
    } else {
      res.status(500).json({ error: 'Internal server error' });
    }
  }
});

app.delete('/api/custom-categories/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM custom_categories WHERE id = $1 AND user_id = $2',
      [id, req.user.userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Category not found' });
    }

    res.json({ message: 'Category deleted successfully' });
  } catch (error) {
    console.error('Delete custom category error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/check', async (req, res) => {
  try {
    const existingAdmin = await pool.query(
      'SELECT id FROM users WHERE role = $1 AND is_demo = FALSE',
      ['admin']
    );
    res.json({ exists: existingAdmin.rows.length > 0 });
  } catch (error) {
    res.status(500).json({ exists: false });
  }
});

// Admin Recovery Phrase and Password Reset
const RECOVERY_KEYWORD_HASH_ITER = 100000;
const RECOVERY_KEYWORD_HASH_ALGO = 'sha256';
const RECOVERY_KEYWORD_SALT = process.env.RECOVERY_KEYWORD_SALT || 'changeme';
const { pbkdf2Sync } = require('crypto');

function hashRecoveryKeywords(keywords) {
  // Sort and join keywords for order-agnostic hash
  const sorted = [...keywords].map(w => w.trim().toLowerCase()).sort().join(' ');
  return pbkdf2Sync(sorted, RECOVERY_KEYWORD_SALT, RECOVERY_KEYWORD_HASH_ITER, 64, RECOVERY_KEYWORD_HASH_ALGO).toString('hex');
}

// Store recovery hash and security answers during admin setup
// (Extend /api/register-admin or create a new endpoint as needed)

// Password recovery endpoint
app.post('/api/admin/recover', async (req, res) => {
  try {
    const { keywords, questions, newPassword } = req.body;
    if (!Array.isArray(keywords) || keywords.length !== 6 || !Array.isArray(questions) || questions.length !== 3 || !newPassword) {
      return res.status(400).json({ error: '6 keywords, 3 questions, and newPassword are required' });
    }
    // Fetch admin recovery data
    const result = await pool.query('SELECT id, recovery_hash, recovery_questions, recovery_answers FROM users WHERE role = $1 AND is_demo = FALSE', ['admin']);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No admin account found' });
    }
    const admin = result.rows[0];
    // Verify keywords
    const hash = hashRecoveryKeywords(keywords);
    if (hash !== admin.recovery_hash) {
      return res.status(403).json({ error: 'Invalid recovery keywords' });
    }
    // Verify security questions
    const expectedAnswers = (admin.recovery_answers || '').split(',').map(a => a.trim().toLowerCase());
    for (let i = 0; i < 3; i++) {
      if (questions[i].trim().toLowerCase() !== expectedAnswers[i]) {
        return res.status(403).json({ error: 'Incorrect answer to security question' });
      }
    }
    // Update password
    await pool.query('UPDATE users SET password = $1, must_reset_password = FALSE, password_changed_at = CURRENT_TIMESTAMP, session_version = session_version + 1 WHERE id = $2', [newPassword, admin.id]);
    await logActivity(admin.id, 'ADMIN_PASSWORD_RECOVERY', 'Password reset via recovery phrase', req);
    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Admin recovery error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
