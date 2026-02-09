# KeyPouch Security Architecture: End-to-End Encrypted Secrets Management

## Document Version
Version 1.0 | Date: February 9, 2026 | Status: Implementation Specification

---

## 1. Executive Summary

KeyPouch implements a **Zero-Knowledge Architecture** with **AES-256 End-to-End Encryption** for secure secrets management. The system ensures that:
- The server has **zero knowledge** of unencrypted secret content
- All encryption/decryption occurs exclusively on the **client-side**
- Shared secrets are **one-time viewable** and destroyed immediately after access
- All actions are logged with **immutable, HIPAA-compliant audit trails**
- JWT authentication protects every endpoint

---

## 2. Architectural Principles

### 2.1 Zero-Knowledge Design
- **Client-side Encryption**: All secrets are encrypted on the client before transmission
- **Key Management**: Encryption keys are derived on the client using PBKDF2
- **Server Ignorance**: Server stores only encrypted data and cannot decrypt secrets
- **No Key Transmission**: Encryption keys never transmitted to or stored on server

### 2.2 End-to-End Encryption (E2EE)
- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Derivation**: PBKDF2-SHA256 (100,000 iterations)
- **IV/Nonce**: Cryptographically random, 16 bytes
- **Authentication Tag**: GCM provides built-in authentication

### 2.3 Shared Secret Lifecycle
1. **Generation**: Server creates cryptographically signed sharing token (RS256)
2. **Transmission**: Encrypted secret + token transmitted to recipient
3. **First Access**: Server validates token, decrypts share record, logs access
4. **Destruction**: One-time-view shares deleted immediately after access
5. **Verification**: Audit log confirms destruction with immutable timestamp

---

## 3. Core Features & Implementation

### 3.1 Share Secrets

#### Sharing Modal Dialog
```
┌─────────────────────────────────────────┐
│ Share Secret: AWS Production API Key    │
├─────────────────────────────────────────┤
│ Expiration Settings:                     │
│  ○ 1 Hour   ○ 24 Hours   ○ 7 Days       │
│  ⏱ Custom: [_____________]               │
│  ☑ One-Time View (destroy after access) │
│                                          │
│ Share Link:                              │
│ https://keypouch.app/share/[TOKEN]      │
│ [📋 Copy Link to Clipboard]              │
│                                          │
│ Email Recipient (optional):              │
│ [_____________________________@_____.com] │
│ [Send via Email]                         │
│                                          │
│ Expiration Timer: 23h 45m remaining      │
│ Status: ✓ Active                         │
└─────────────────────────────────────────┘
```

#### API Specification
**POST /api/secrets/:id/share**
```
Request:
{
  "expiresInMinutes": 1440,        // null for no expiration
  "maxViews": 1,                   // 1 for one-time view
  "allowedEmails": ["user@ex.com"] // optional whitelist
}

Response (201 Created):
{
  "token": "eyJhbGciOiJSUzI1NiIs...",  // RS256 signed JWT
  "shareUrl": "https://keypouch.app/share/[token]",
  "expiresAt": "2026-02-10T05:30:00Z",
  "createdAt": "2026-02-09T05:30:00Z",
  "viewsRemaining": 1
}
```

#### Security Implementation
- **Token Signing**: RS256 (RSA-2048) signature prevents tampering
- **Token Claims**: Include secret_id, expires_at, max_views, created_by
- **Stateless Validation**: Token contains all needed information
- **Rate Limiting**: Max 10 share requests per minute per user

---

### 3.2 View Secrets

#### Shared Secret Access Flow
```
User clicks share link
    ↓
[GET /api/shared-secrets/:token]
    ↓
Server validates token signature
    ↓
Server checks:
  - Token not expired
  - View count not exceeded
  - User IP not flagged as suspicious
    ↓
Server returns encrypted secret + metadata
    ↓
Client decrypts using local key (zero-server-knowledge)
    ↓
User views plaintext secret
    ↓
Server logs access with timestamp
    ↓
Server deletes share record (one-time view)
    ↓
Server logs destruction with verification hash
```

#### API Specification
**GET /api/shared-secrets/:token**
```
Response (200 OK):
{
  "id": "share_123abc",
  "secretId": 456,
  "title": "AWS Production API Key",
  "encryptedContent": "U2FsdGVkX1...",  // AES-256-GCM
  "iv": "abc123def456ghi789jkl",        // base64
  "authTag": "xyz789uvw456rst123qop",   // base64
  "encryptedBy": "user@company.com",
  "sharedAt": "2026-02-09T05:30:00Z",
  "expiresAt": "2026-02-10T05:30:00Z",
  "viewsRemaining": 1
}

Response Error (410 Gone - share destroyed):
{
  "error": "shared_secret_accessed",
  "message": "This shared secret was already viewed and destroyed",
  "destroyedAt": "2026-02-09T06:15:22Z",
  "viewedBy": "[REDACTED - logged in audit trail]"
}

Response Error (401 Unauthorized):
{
  "error": "invalid_share_token",
  "message": "Share token signature validation failed",
  "reason": "token_tampered_or_expired"
}
```

#### One-Time View Destruction
```javascript
// On successful access:
1. Log access event with timestamp
2. Compute destruction verification hash: HMAC-SHA256(share_record)
3. Delete share record from database
4. Log destruction event with verification hash
5. Return 410 Gone on subsequent access attempts
```

---

### 3.3 Edit Secrets

#### Edit Modal Implementation
- Icon: `Edit` next to each secret in list
- Functionality: Opens modal with encrypted current values
- Validation: Check user has `modify` or `admin` role
- Versioning: Maintain edit history (encrypted)
- Audit Trail: Log edit before, after, timestamp, user

#### API Specification
**PUT /api/secrets/:id**
```
Request:
{
  "title": "Updated Secret Title",
  "category": "api_key",
  "encryptedContent": {
    "data": "U2FsdGVkX1...",    // AES-256-GCM encrypted
    "iv": "abc123def456...",     // base64
    "authTag": "xyz789uvw...",   // base64
    "algorithm": "AES-256-GCM"
  },
  "username": "admin",
  "url": "https://api.example.com",
  "notes": "Updated notes"
}

Response (200 OK):
{
  "id": 456,
  "title": "Updated Secret Title",
  "category": "api_key",
  "updated_at": "2026-02-09T05:45:00Z",
  "version": 2
}

Audit Log Entry:
{
  "action": "SECRET_UPDATED",
  "details": {
    "secretId": 456,
    "changedFields": ["title", "category"],
    "previousVersion": 1,
    "newVersion": 2
  },
  "timestamp": "2026-02-09T05:45:00Z"
}
```

---

### 3.4 Copy to Clipboard

#### Implementation Strategy
```
┌─────────────────────────────────────────┐
│ Secret: AWS Production API Key          │
│ ••••••••••••••••• [👁 View]             │
│ ••••••••••••••• [📋 Copy] ← SECURE     │
│                                         │
│  ⚠️ Clipboard will clear in 60 seconds  │
└─────────────────────────────────────────┘
```

#### Copy-to-Clipboard Mechanism
```javascript
// Client-side implementation (NO server logging of content)
const copyToClipboard = async (secretContent) => {
  // 1. Copy to system clipboard using Clipboard API
  await navigator.clipboard.writeText(secretContent);
  
  // 2. Show user feedback: green checkmark for 2 seconds
  showNotification('✓ Copied to clipboard');
  
  // 3. Auto-clear clipboard after 60 seconds
  setTimeout(() => {
    navigator.clipboard.writeText('');  // Clear clipboard
    showNotification('⚠️ Clipboard cleared for security');
  }, 60000);
  
  // 4. Log action WITHOUT content in server audit log
  logAudit('SECRET_COPIED', {
    secretId: 456,
    secretType: 'api_key',  // Not the actual secret
    timestamp: new Date().toISOString()
  });
};
```

#### Security Considerations
- **No Content Logging**: Server log contains only action, not secret content
- **Clipboard Wiping**: Automatic clear after 60s to prevent accidental paste
- **No History Traces**: Uses modern Clipboard API (not legacy execCommand)
- **Access Validation**: User must have `view` role minimum
- **Audit Trail**: Only action logged, never the copied content

---

### 3.5 Delete Secrets

#### Delete Operation
```
User clicks [🗑️ Delete]
    ↓
Modal confirmation: "Permanently delete this secret?"
    ↓
If confirmed:
  1. Server validates authorization (admin/modify role)
  2. Server logs deletion event with secret metadata (not content)
  3. Server soft-deletes record OR hard-deletes based on config
  4. Server logs audit entry with timestamp and user
  5. If shared secrets exist, revoke all shares and log
```

#### API Specification
**DELETE /api/secrets/:id**
```
Response (200 OK):
{
  "message": "Secret deleted successfully",
  "deletedAt": "2026-02-09T05:50:00Z",
  "shareLinksRevoked": 1,
  "auditId": "audit_789xyz"
}

Audit Log:
{
  "action": "SECRET_DELETED",
  "details": {
    "secretId": 456,
    "title": "AWS Production API Key",    // Metadata only
    "category": "api_key",
    "deletedBy": "admin@company.com",
    "sharesRevoked": 1
  },
  "timestamp": "2026-02-09T05:50:00Z"
}
```

---

## 4. Database Schema

### 4.1 Encrypted Secrets Table (Enhanced)
```sql
CREATE TABLE secrets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    category VARCHAR(50) DEFAULT 'general',
    
    -- Encrypted content storage
    encrypted_content TEXT NOT NULL,  -- AES-256-GCM encrypted
    content_iv VARCHAR(255) NOT NULL, -- base64 encoded
    content_auth_tag VARCHAR(255) NOT NULL, -- base64 GCM auth tag
    
    -- Decrypted metadata (optional, for subset of info)
    username VARCHAR(255),
    password TEXT,
    api_key TEXT,
    url TEXT,
    notes TEXT,
    
    -- Versioning
    version INTEGER DEFAULT 1,
    previous_version_id INTEGER REFERENCES secrets(id),
    
    -- Status & Timestamps
    is_deleted BOOLEAN DEFAULT FALSE,
    deleted_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Encryption metadata
    encryption_algorithm VARCHAR(20) DEFAULT 'AES-256-GCM',
    key_derivation_version INTEGER DEFAULT 1,
    
    CONSTRAINT secrets_valid_encryption CHECK (
        encryption_algorithm IN ('AES-256-GCM')
    )
);

CREATE INDEX idx_secrets_user_id ON secrets(user_id);
CREATE INDEX idx_secrets_category ON secrets(category);
CREATE INDEX idx_secrets_created_at ON secrets(created_at DESC);
```

### 4.2 Shared Secrets Table (New)
```sql
CREATE TABLE shared_secrets (
    id VARCHAR(63) PRIMARY KEY,  -- Derived from RS256 token
    secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    created_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Share constraints
    max_views INTEGER DEFAULT 1,  -- 1 for one-time view
    views_count INTEGER DEFAULT 0,
    viewed_at TIMESTAMP NULL,
    viewed_by_ip VARCHAR(45) NULL,
    
    -- Expiration
    expires_at TIMESTAMP NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP NULL,
    
    -- Access control
    allowed_emails TEXT[] NULL,  -- Array of whitelisted emails
    require_password BOOLEAN DEFAULT FALSE,
    password_hash VARCHAR(255) NULL,
    
    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    destroyed_at TIMESTAMP NULL,
    destruction_hash VARCHAR(64) NULL,  -- HMAC-SHA256 verification
    
    CONSTRAINT valid_views CHECK (views_count <= max_views OR max_views IS NULL)
);

CREATE INDEX idx_shared_secrets_secret_id ON shared_secrets(secret_id);
CREATE INDEX idx_shared_secrets_created_by ON shared_secrets(created_by);
CREATE INDEX idx_shared_secrets_expires_at ON shared_secrets(expires_at);
CREATE INDEX idx_shared_secrets_destroyed_at ON shared_secrets(destroyed_at);
```

### 4.3 Audit Logs Table (Enhanced)
```sql
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(100) NOT NULL,
    
    -- Action tracking
    action VARCHAR(100) NOT NULL,  -- SECRET_CREATED, SECRET_VIEWED, SECRET_SHARED, etc.
    resource_type VARCHAR(50),     -- 'secret', 'share', 'user'
    resource_id VARCHAR(100),      -- secret_id or share_id
    
    -- Detailed audit information
    details JSONB,  -- Structured data for action-specific details
    
    -- Security & Compliance
    ip_address VARCHAR(45),        -- IPv4 or IPv6
    user_agent TEXT,
    status VARCHAR(20),            -- 'success', 'failure', 'denied'
    error_message TEXT NULL,
    
    -- HIPAA Compliance
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    transaction_id VARCHAR(100),   -- Trace transactions
    
    -- Immutability & Verification
    log_hash VARCHAR(64),          -- SHA-256 of log entry for verification
    previous_log_hash VARCHAR(64), -- Hash chain for immutability
    
    CONSTRAINT valid_action CHECK (action ~ '^[A-Z_]+$'),
    CONSTRAINT valid_status CHECK (status IN ('success', 'failure', 'denied'))
);

CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_username ON audit_logs(username);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);

-- Hash chain for immutability verification
CREATE UNIQUE INDEX idx_audit_logs_hash_chain 
ON audit_logs(previous_log_hash);
```

---

## 5. API Endpoints

### 5.1 Authentication Required Endpoints

#### Share Management
- `POST /api/secrets/:id/share` - Create share link
- `GET /api/secrets/:id/shares` - List share links
- `DELETE /api/secrets/:id/shares/:shareId` - Revoke share
- `PATCH /api/secrets/:id/shares/:shareId` - Update share settings

#### Shared Secret Access (No auth required but token validated)
- `GET /api/shared-secrets/:token` - Access shared secret
- `POST /api/shared-secrets/:token/validate` - Pre-check availability

#### Audit & Compliance
- `GET /api/audit-logs?filters...` - Query audit logs (admin only)
- `GET /api/audit-logs/verify/:logId` - Verify log integrity
- `GET /api/secrets/:id/audit` - Audit trail for specific secret

### 5.2 Request/Response Headers
```
All requests (except /api/shared-secrets/:token):
  Authorization: Bearer <JWT_TOKEN>
  Content-Type: application/json
  X-Request-ID: <UUID>  -- For transaction tracing

Audit Trail Response Headers:
  X-Audit-ID: <audit_log_id>
  X-Log-Hash: <SHA256_of_log>
```

---

## 6. Client-Side Encryption Implementation

### 6.1 Key Derivation
```javascript
// Client-side PBKDF2 key derivation
async function deriveEncryptionKey(password, salt) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  
  // PBKDF2 with 100,000 iterations
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    data,
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );
  
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: new Uint8Array(salt),
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,  // extractable for local ops only
    ['encrypt', 'decrypt']
  );
  
  return key;
}
```

### 6.2 Encryption Process
```javascript
async function encryptSecret(plaintext, key) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);
  
  // Generate random IV
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  // Encrypt with AES-256-GCM
  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    data
  );
  
  return {
    encrypted: Buffer.from(encryptedData).toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
    authTag: extractAuthTag(encryptedData)  // GCM provides auth
  };
}
```

### 6.3 Decryption Process (Client-side only)
```javascript
async function decryptSecret(encrypted, iv, key) {
  const encryptedData = Buffer.from(encrypted, 'base64');
  const ivBuffer = Buffer.from(iv, 'base64');
  
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBuffer },
    key,
    encryptedData
  );
  
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}
```

---

## 7. Security Considerations & Threat Mitigation

### 7.1 Threat: One-Time View Bypass
**Mitigation:**
- Use stateless token validation (token contains max_views)
- Increment view_count atomically in database
- Use database lock to prevent race conditions
- Log destruction with cryptographic hash for immutability

### 7.2 Threat: Key Extraction from Server
**Mitigation:**
- Server stores ONLY encrypted data
- Server never stores or sees encryption keys
- Keys derived client-side using PBKDF2
- Zero transmission of key material to server

### 7.3 Threat: Token Tampering
**Mitigation:**
- Use RS256 signatures (asymmetric)
- Validate token signature on every access
- Include exp, iat, aud in token claims
- Reject modified or expired tokens

### 7.4 Threat: Clipboard Exposure
**Mitigation:**
- Use modern Clipboard API (not old execCommand)
- Auto-clear clipboard after 60 seconds
- Never log clipboard content
- Log only the action, not the data

### 7.5 Threat: Concurrent Access Race Condition
**Mitigation:**
- Use database SELECT ... FOR UPDATE (PostgreSQL row lock)
- Increment views_count atomically
- Return failure if view_count >= max_views
- Execute deletion within same transaction

### 7.6 Threat: Audit Log Tampering
**Mitigation:**
- Implement hash chain (previous_log_hash)
- Each entry includes hash of previous entry
- Any modification breaks the chain
- Use immutable storage or append-only tables

---

## 8. Audit Logging Strategy

### 8.1 Logged Actions
```
SECRET_CREATED: New secret created
  - secretId, title, category, createdBy, timestamp
  
SECRET_UPDATED: Secret content or metadata modified
  - secretId, changedFields, previousVersion, newVersion
  
SECRET_VIEWED: Secret accessed (in UI, not shared)
  - secretId, viewedBy, viewedAt, ipAddress
  
SECRET_SHARED: Share link created
  - secretId, shareToken, expiresAt, maxViews, createdBy
  
SHARED_SECRET_ACCESSED: Shared link clicked
  - shareToken, accessedAt, accessedFrom, viewCount
  
SHARED_SECRET_DESTROYED: One-time view share destroyed
  - shareToken, destroyedAt, verificationHash, viewedBy
  
SECRET_COPIED: Content copied to clipboard
  - secretId (not content!), copiedBy, copiedAt
  
SECRET_DELETED: Secret permanently deleted
  - secretId, title, deletedBy, deletedAt, sharesRevoked
  
SHARE_REVOKED: Share link revoked before expiration
  - shareToken, revokedBy, revokedAt, reason
  
ACCESS_DENIED: Unauthorized access attempt
  - resource, attemptedBy, deniedAt, reason, ipAddress
```

### 8.2 Audit Log Format
```json
{
  "id": 12345,
  "timestamp": "2026-02-09T06:30:45.123Z",
  "userId": 42,
  "username": "user@company.com",
  "action": "SECRET_SHARED",
  "resourceType": "secret",
  "resourceId": "456",
  "details": {
    "secretTitle": "AWS Production API Key",
    "shareToken": "share_abc123...",
    "expiresAt": "2026-02-10T06:30:45Z",
    "maxViews": 1,
    "allowedEmails": ["recipient@company.com"]
  },
  "ipAddress": "192.168.1.100",
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
  "status": "success",
  "transactionId": "txn_xyz789",
  "logHash": "sha256_hash_of_this_entry",
  "previousLogHash": "sha256_hash_of_previous_entry"
}
```

### 8.3 HIPAA Compliance Requirements
- ✓ Timestamp on all events (immutable)
- ✓ User identification (who performed action)
- ✓ Action identification (what was done)
- ✓ Resource identification (which secret)
- ✓ Result (success/failure)
- ✓ IP address and device info
- ✓ Cannot be modified or deleted
- ✓ Retention: Minimum 6 years per HIPAA
- ✓ Encrypted at rest and in transit

---

## 9. Implementation Roadmap

### Phase 1: Core Sharing (Current Sprint)
1. ✓ Database schema for shared_secrets table
2. ✓ Generate and validate RS256 tokens
3. ✓ Create share endpoint
4. ✓ Access shared secret endpoint
5. ✓ One-time view destruction with verification

### Phase 2: Enhanced UI/UX
6. ✓ Sharing modal with expiration timer
7. ✓ Inline action buttons (edit, view, copy, delete)
8. ✓ Copy-to-clipboard with auto-clear
9. ✓ Delete confirmation modal

### Phase 3: Audit & Compliance
10. ✓ Enhanced audit logging with JSONB details
11. ✓ Hash chain for log immutability
12. ✓ Audit log verification endpoint

### Phase 4: Advanced Features
13. Email notifications for shared secrets
14. Password-protected shares
15. IP whitelist for shares
16. Expiration timer countdown in modal

---

## 10. Encryption Key Management

### 10.1 Master Key Considerations
```
Option A: User-derived keys (Recommended for Zero-Knowledge)
  - User's password → PBKDF2 → Encryption key
  - No master key needed
  - Lost password = lost secrets (user recovers via backup)

Option B: Backup codes
  - User generates 10 backup codes during onboarding
  - Each code can decrypt secrets if password lost
  - Codes stored encrypted with separate master key
  - User stores backup codes securely offline

Option C: Hardware security
  - Optional FIDO2 key integration
  - Second factor for sensitive secret access
  - Supplements password-based encryption
```

---

## 11. Testing & Validation

### 11.1 Security Testing Checklist
- [ ] Token tampering test: Modify JWT, verify rejection
- [ ] One-time view: Access shared secret, verify destroyed on 2nd access
- [ ] Concurrent access: Simulate 100 simultaneous accesses, verify only 1 succeeds
- [ ] Key leakage: Verify server logs never contain plaintext secrets
- [ ] Expiration: Verify expired shares return 410 Gone
- [ ] Hash chain: Verify breaking chain is detected
- [ ] Clipboard: Verify auto-clear after 60s

### 11.2 Compliance Testing
- [ ] HIPAA audit trail completeness
- [ ] Log immutability verification
- [ ] Encryption strength validation
- [ ] Data retention policy enforcement

---

## 12. References & Standards

- **AES-256-GCM**: NIST FIPS 197
- **PBKDF2**: RFC 2898
- **RS256**: RFC 7518 (JSON Web Signature)
- **HIPAA**: 45 CFR § 164.312(b) - Audit Controls
- **Zero-Knowledge Proofs**: Ben-Sasson et al. (2014)
- **Clipboard Security**: OWASP Top 10 - A08:2021 Software & Data Integrity Failures

---

**Document Owner**: Security Architecture Team  
**Last Updated**: February 9, 2026  
**Next Review**: May 9, 2026
