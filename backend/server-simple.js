const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;

const ROLE_VIEW = 'view';
const ROLE_MODIFY = 'modify';
const ROLE_FULL = 'full-access';
const ROLE_ADMIN = 'admin';

// Middleware
app.use(cors());
app.use(express.json());

// JWT Secret
const JWT_SECRET = 'your-secret-key-change-in-production';

// In-memory data store for testing
let users = [
  { id: 1, username: 'admin', password: 'admin', role: ROLE_ADMIN, is_disabled: false, must_reset_password: false, mfa_enabled: false, mfa_secret: null, session_version: 0, last_login_at: null, created_at: new Date().toISOString() },
  { id: 2, username: 'viewuser', password: 'viewuser', role: ROLE_VIEW, is_disabled: false, must_reset_password: false, mfa_enabled: false, mfa_secret: null, session_version: 0, last_login_at: null, created_at: new Date().toISOString() }
];

let contacts = [
  { id: 1, user_id: 1, name: 'Sarah Connor', phone: '(555) 123-4567', address: '123 Tech Blvd, Silicon Valley, CA', created_at: new Date().toISOString() },
  { id: 2, user_id: 1, name: 'John Wick', phone: '(555) 987-6543', address: 'Continental Hotel, New York, NY', created_at: new Date().toISOString() }
];

let secrets = [
  { id: 1, user_id: 1, title: 'Corporate WiFi', category: 'general', notes: 'Guest network password for the 5th floor.', password: 'secure-guest-wifi', created_at: new Date().toISOString() },
  { id: 2, user_id: 1, title: 'AWS Production Access', category: 'api', api_key: 'AKIAJ567890123EXAMPLE', notes: 'Read-only access for dashboard metrics.', created_at: new Date().toISOString() }
];

let auditLogs = [
  { id: 1, username: 'admin', action: 'SYSTEM_INIT', details: 'System initialized', timestamp: new Date().toISOString(), ip: '127.0.0.1' }
];

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const dbUser = users.find(u => u.id === user.id);
    if (!dbUser) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const tokenVersion = user.sv ?? 0;
    if (dbUser.is_disabled) {
      return res.status(403).json({ error: 'Account disabled' });
    }
    if (dbUser.session_version !== tokenVersion) {
      return res.status(401).json({ error: 'Session expired' });
    }

    req.user = { id: dbUser.id, username: dbUser.username, role: dbUser.role || ROLE_VIEW };
    next();
  });
};

const canView = (role) => role === ROLE_VIEW || role === ROLE_MODIFY || role === ROLE_FULL || role === ROLE_ADMIN;
const canModify = (role) => role === ROLE_MODIFY || role === ROLE_FULL || role === ROLE_ADMIN;
const canDelete = (role) => role === ROLE_FULL || role === ROLE_ADMIN;

const requirePermission = (permission) => (req, res, next) => {
  const role = req.user?.role || ROLE_VIEW;
  if (permission === 'view' && !canView(role)) return res.status(403).json({ error: 'Insufficient permissions' });
  if (permission === 'modify' && !canModify(role)) return res.status(403).json({ error: 'Insufficient permissions' });
  if (permission === 'delete' && !canDelete(role)) return res.status(403).json({ error: 'Insufficient permissions' });
  return next();
};

// Helper function to log activity
const logActivity = (username, action, details) => {
  const newLog = {
    id: auditLogs.length + 1,
    username,
    action,
    details,
    timestamp: new Date().toISOString(),
    ip: '10.0.0.' + Math.floor(Math.random() * 255)
  };
  auditLogs.unshift(newLog);
  if (auditLogs.length > 200) auditLogs.pop();
};

// Auth Routes
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = users.find(u => u.username === username);
    
    if (!user || user.password !== password) {
      logActivity(username || 'unknown', 'LOGIN_FAILED', 'Failed login attempt');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.is_disabled) {
      logActivity(user.username, 'LOGIN_BLOCKED', 'Login blocked: account disabled');
      return res.status(403).json({ error: 'Account disabled' });
    }

    logActivity(user.username, 'LOGIN', 'User logged in successfully');
    user.last_login_at = new Date().toISOString();

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role || ROLE_VIEW, sv: user.session_version || 0 },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      username: user.username,
      role: user.role || ROLE_VIEW,
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

    const user = users.find(u => u.username === username);
    if (!user || !user.security_question) {
      return res.status(404).json({ error: 'User not found or no security question set' });
    }

    res.json({ question: user.security_question });
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

    const user = users.find(u => u.username === username);
    if (!user || !user.security_answer) {
      return res.status(404).json({ error: 'User not found or no security answer set' });
    }

    const expected = String(user.security_answer).trim().toLowerCase();
    const provided = String(answer).trim().toLowerCase();
    if (expected !== provided) {
      logActivity(username, 'SECURITY_FAIL', 'Security question check failed');
      return res.status(403).json({ error: 'Incorrect answer' });
    }

    const token = jwt.sign(
      { typ: 'pwd_reset', id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    logActivity(username, 'SECURITY_VERIFY', 'Security question verified');
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

    const idx = users.findIndex(u => u.id === decoded.id);
    if (idx === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    users[idx].password = newPassword;
    users[idx].must_reset_password = false;
    users[idx].password_changed_at = new Date().toISOString();
    users[idx].session_version += 1;
    logActivity(users[idx].username, 'PASSWORD_RESET', 'Password successfully reset');

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/me/change-password', authenticateToken, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!new_password) {
      return res.status(400).json({ error: 'new_password is required' });
    }

    const idx = users.findIndex(u => u.id === req.user.id);
    if (idx === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!users[idx].must_reset_password) {
      if (!current_password) {
        return res.status(400).json({ error: 'current_password is required' });
      }
      if (String(current_password) !== String(users[idx].password)) {
        return res.status(403).json({ error: 'Current password is incorrect' });
      }
    }

    users[idx].password = new_password;
    users[idx].must_reset_password = false;
    users[idx].password_changed_at = new Date().toISOString();
    users[idx].session_version += 1;

    logActivity(users[idx].username, 'PASSWORD_CHANGE', 'User changed password');

    const nextToken = jwt.sign(
      { id: users[idx].id, username: users[idx].username, role: users[idx].role || ROLE_VIEW, sv: users[idx].session_version || 0 },
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
    
    if (users.find(u => u.username === username)) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const newUser = { 
      id: users.length + 1, 
      username, 
      password, 
      role: ROLE_VIEW,
      is_disabled: false,
      must_reset_password: false,
      mfa_enabled: false,
      mfa_secret: null,
      session_version: 0,
      last_login_at: null,
      created_at: new Date().toISOString(),
      security_question: securityQuestion || null,
      security_answer: securityAnswer || null
    };
    users.push(newUser);

    logActivity(newUser.username, 'REGISTER', 'User registered');

    const token = jwt.sign(
      { id: newUser.id, username: newUser.username, role: newUser.role, sv: newUser.session_version || 0 },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

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

    const usersWithoutPasswords = users.map(({ password, security_answer, mfa_secret, ...u }) => u);
    res.json(usersWithoutPasswords);
  } catch (error) {
    console.error('Get users error:', error);
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
    if (users.find(u => u.username === username)) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const newUser = {
      id: users.length + 1,
      username,
      password,
      role: role || ROLE_VIEW,
      is_disabled: !!is_disabled,
      must_reset_password: !!must_reset_password,
      mfa_enabled: false,
      mfa_secret: null,
      session_version: 0,
      last_login_at: null,
      created_at: new Date().toISOString()
    };
    users.push(newUser);

    logActivity(req.user.username, 'USER_CREATE', `Created user: ${username}`);
    const { password: _pw, mfa_secret: _mfa, security_answer, ...safe } = newUser;
    res.status(201).json({ message: 'User created', user: safe });
  } catch (error) {
    console.error('Create user error:', error);
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

    const userIndex = users.findIndex(u => u.id === parseInt(id));
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    const oldRole = users[userIndex].role;
    users[userIndex].role = role;

    logActivity(req.user.username, 'USER_UPDATE', `Changed role for ${users[userIndex].username} from ${oldRole} to ${role}`);

    res.json({
      message: 'User updated',
      user: { ...users[userIndex], password: undefined, security_answer: undefined, mfa_secret: undefined }
    });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

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

    const userIndex = users.findIndex(u => u.id === parseInt(id));
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    const before = users[userIndex];
    if (role !== undefined) users[userIndex].role = role;
    if (is_disabled !== undefined) users[userIndex].is_disabled = !!is_disabled;
    if (must_reset_password !== undefined) users[userIndex].must_reset_password = !!must_reset_password;

    // If we disable/enable or force reset, revoke sessions so change takes effect immediately.
    if (
      (is_disabled !== undefined && !!is_disabled !== before.is_disabled) ||
      (must_reset_password !== undefined && !!must_reset_password !== before.must_reset_password)
    ) {
      users[userIndex].session_version += 1;
    }

    logActivity(req.user.username, 'USER_UPDATE', `Patched user ${users[userIndex].username}`);

    res.json({
      message: 'User updated',
      user: { ...users[userIndex], password: undefined, security_answer: undefined, mfa_secret: undefined }
    });
  } catch (error) {
    console.error('Patch user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { id } = req.params;
    const user = users.find(u => u.id === parseInt(id));
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const { password, security_answer, mfa_secret, ...safe } = user;
    res.json(safe);
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
    const user = users.find(u => u.id === parseInt(id));
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const logs = auditLogs.filter(l => l.username === user.username).slice(0, 200);
    res.json(logs);
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
    const userIndex = users.findIndex(u => u.id === parseInt(id));
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    users[userIndex].is_disabled = !!is_disabled;
    users[userIndex].session_version += 1;
    logActivity(req.user.username, 'USER_STATUS', `Set ${users[userIndex].username} disabled=${!!is_disabled}`);

    res.json({ message: 'User status updated', user: { ...users[userIndex], password: undefined, security_answer: undefined, mfa_secret: undefined } });
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

    const userIndex = users.findIndex(u => u.id === parseInt(id));
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    users[userIndex].password = new_password;
    users[userIndex].must_reset_password = true;
    users[userIndex].password_changed_at = new Date().toISOString();
    users[userIndex].session_version += 1;
    logActivity(req.user.username, 'PASSWORD_RESET_ADMIN', `Admin reset password for ${users[userIndex].username}`);

    res.json({ message: 'Password reset', user: { id: users[userIndex].id, username: users[userIndex].username } });
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
    const userIndex = users.findIndex(u => u.id === parseInt(id));
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    users[userIndex].session_version += 1;
    logActivity(req.user.username, 'SESSIONS_REVOKED', `Revoked sessions for ${users[userIndex].username}`);

    res.json({ message: 'Sessions revoked', user: { id: users[userIndex].id, username: users[userIndex].username } });
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
    const userIndex = users.findIndex(u => u.id === parseInt(id));
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    users[userIndex].mfa_enabled = false;
    users[userIndex].mfa_secret = null;
    logActivity(req.user.username, 'MFA_RESET', `Reset MFA for ${users[userIndex].username}`);

    res.json({ message: 'MFA reset', user: { id: users[userIndex].id, username: users[userIndex].username } });
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
    const userIndex = users.findIndex(u => u.id === parseInt(id));

    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    const deletedUser = users[userIndex].username;
    users.splice(userIndex, 1);

    logActivity(req.user.username, 'USER_DELETE', `Deleted user: ${deletedUser}`);

    res.json({ message: 'User deleted' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Contacts Routes
app.get('/api/contacts', authenticateToken, requirePermission('view'), async (req, res) => {
  try {
    const { search } = req.query;
    let userContacts = contacts.filter(c => c.user_id === req.user.id);

    if (search) {
      userContacts = userContacts.filter(c => 
        c.name.toLowerCase().includes(search.toLowerCase()) || 
        c.phone.includes(search) || 
        c.address?.toLowerCase().includes(search.toLowerCase())
      );
    }

    res.json(userContacts);
  } catch (error) {
    console.error('Get contacts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/contacts', authenticateToken, requirePermission('modify'), async (req, res) => {
  try {
    const { name, phone, address } = req.body;

    const newContact = {
      id: contacts.length + 1,
      user_id: req.user.id,
      name,
      phone,
      address,
      created_at: new Date().toISOString()
    };

    contacts.push(newContact);
    logActivity(req.user.username, 'CONTACT_CREATE', `Created contact: ${newContact.name}`);

    res.status(201).json({
      message: 'Contact created',
      contact: newContact
    });
  } catch (error) {
    console.error('Create contact error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/contacts/:id', authenticateToken, requirePermission('modify'), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, phone, address } = req.body;

    const contactIndex = contacts.findIndex(c => 
      c.id === parseInt(id) && c.user_id === req.user.id
    );

    if (contactIndex === -1) {
      return res.status(404).json({ error: 'Contact not found' });
    }

    contacts[contactIndex] = { ...contacts[contactIndex], name, phone, address };
    logActivity(req.user.username, 'CONTACT_UPDATE', `Updated contact: ${contacts[contactIndex].name}`);

    res.json({ message: 'Contact updated' });
  } catch (error) {
    console.error('Update contact error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/contacts/:id', authenticateToken, requirePermission('delete'), async (req, res) => {
  try {
    const { id } = req.params;
    const contactIndex = contacts.findIndex(c => 
      c.id === parseInt(id) && c.user_id === req.user.id
    );

    if (contactIndex === -1) {
      return res.status(404).json({ error: 'Contact not found' });
    }

    const name = contacts[contactIndex].name;
    contacts.splice(contactIndex, 1);

    logActivity(req.user.username, 'CONTACT_DELETE', `Deleted contact: ${name}`);

    res.json({ message: 'Contact deleted' });
  } catch (error) {
    console.error('Delete contact error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Secrets Routes
app.get('/api/secrets', authenticateToken, requirePermission('view'), async (req, res) => {
  try {
    const { search, category } = req.query;
    let userSecrets = secrets.filter(s => s.user_id === req.user.id);

    if (search) {
      userSecrets = userSecrets.filter(s => 
        s.title.toLowerCase().includes(search.toLowerCase())
      );
    }

    if (category) {
      userSecrets = userSecrets.filter(s => s.category === category);
    }

    res.json(userSecrets);
  } catch (error) {
    console.error('Get secrets error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/secrets/:id', authenticateToken, requirePermission('view'), async (req, res) => {
  try {
    const { id } = req.params;

    const secret = secrets.find(s => 
      s.id === parseInt(id) && s.user_id === req.user.id
    );

    if (!secret) {
      return res.status(404).json({ error: 'Secret not found' });
    }

    logActivity(req.user.username, 'SECRET_VIEW', `Viewed details of secret: ${secret.title}`);

    res.json(secret);
  } catch (error) {
    console.error('Get secret error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/secrets', authenticateToken, requirePermission('modify'), async (req, res) => {
  try {
    const { title, category, username, password, api_key, url, notes } = req.body;

    const newSecret = {
      id: secrets.length + 1,
      user_id: req.user.id,
      title,
      category: category || 'general',
      username,
      password,
      api_key,
      url,
      notes,
      created_at: new Date().toISOString()
    };

    secrets.push(newSecret);
    logActivity(req.user.username, 'SECRET_CREATE', `Created secret: ${newSecret.title}`);

    res.status(201).json({ message: 'Secret created' });
  } catch (error) {
    console.error('Create secret error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/secrets/:id', authenticateToken, requirePermission('modify'), async (req, res) => {
  try {
    const { id } = req.params;
    const { title, category, username, password, api_key, url, notes } = req.body;

    const secretIndex = secrets.findIndex(s => 
      s.id === parseInt(id) && s.user_id === req.user.id
    );

    if (secretIndex === -1) {
      return res.status(404).json({ error: 'Secret not found' });
    }

    secrets[secretIndex] = { 
      ...secrets[secretIndex], 
      title, 
      category, 
      username, 
      password, 
      api_key, 
      url, 
      notes, 
      updated_at: new Date().toISOString() 
    };

    logActivity(req.user.username, 'SECRET_UPDATE', `Updated secret: ${secrets[secretIndex].title}`);

    res.json({ message: 'Secret updated' });
  } catch (error) {
    console.error('Update secret error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/secrets/:id', authenticateToken, requirePermission('delete'), async (req, res) => {
  try {
    const { id } = req.params;
    const secretIndex = secrets.findIndex(s => 
      s.id === parseInt(id) && s.user_id === req.user.id
    );

    if (secretIndex === -1) {
      return res.status(404).json({ error: 'Secret not found' });
    }

    const title = secrets[secretIndex].title;
    secrets.splice(secretIndex, 1);

    logActivity(req.user.username, 'SECRET_DELETE', `Deleted secret: ${title}`);

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
    res.json(auditLogs);
  } catch (error) {
    console.error('Get audit logs error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
