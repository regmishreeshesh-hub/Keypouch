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

const getClientIp = (req) => {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || req.ip || 'unknown';
};

const logActivity = async (username, action, details, req) => {
  try {
    await pool.query(
      'INSERT INTO audit_logs (username, action, details, ip) VALUES ($1, $2, $3, $4)',
      [username, action, details, req ? getClientIp(req) : null]
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

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Database connected successfully at:', res.rows[0].now);
  }
});

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

// Auth Routes
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const result = await pool.query(
      'SELECT id, username, password, role, is_disabled, session_version, must_reset_password FROM users WHERE username = $1',
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
      must_reset_password: user.must_reset_password || false
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

// User Management Routes (Admin Only)
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const result = await pool.query(
      'SELECT id, username, role, created_at, is_disabled, must_reset_password, mfa_enabled, last_login_at FROM users ORDER BY created_at'
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
    res.json(result.rows);
  } catch (error) {
    console.error('Get contacts error:', error);
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
      'SELECT * FROM secrets WHERE id = $1 AND user_id = $2',
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
    const { title, category, username, password, api_key, url, notes } = req.body;

    const result = await pool.query(
      'INSERT INTO secrets (user_id, title, category, username, password, api_key, url, notes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [req.user.id, title, category || 'general', username, password, api_key, url, notes]
    );

    res.status(201).json({ message: 'Secret created' });
  } catch (error) {
    console.error('Create secret error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/secrets/:id', authenticateToken, checkPermission('modify'), async (req, res) => {
  try {
    const { id } = req.params;
    const { title, category, username, password, api_key, url, notes } = req.body;

    const result = await pool.query(
      'UPDATE secrets SET title = $1, category = $2, username = $3, password = $4, api_key = $5, url = $6, notes = $7, updated_at = CURRENT_TIMESTAMP WHERE id = $8 AND user_id = $9 RETURNING *',
      [title, category, username, password, api_key, url, notes, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Secret not found' });
    }

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
      'DELETE FROM secrets WHERE id = $1 AND user_id = $2',
      [id, req.user.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Secret not found' });
    }

    res.json({ message: 'Secret deleted' });
  } catch (error) {
    console.error('Delete secret error:', error);
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

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
