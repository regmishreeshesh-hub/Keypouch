# KeyPouch E2E Encryption Implementation Guide

## Quick Start: Feature Implementation Checklist

### Phase 1: Database & Backend (Current Sprint)
- [x] Create SECURITY_ARCHITECTURE.md specification document
- [x] Create database migration for shared_secrets table
- [x] Implement backend API endpoints for secure sharing
- [ ] Add JWT token signing/verification (RS256)
- [ ] Deploy database migration to production
- [ ] Integration test all endpoints

### Phase 2: Frontend UI Components
- [x] Create ShareModal.tsx component
- [x] Create SecretActions.tsx component with action buttons
- [x] Update secretService.ts with new API methods
- [ ] Integrate components into Secrets.tsx list view
- [ ] Test clipboard operations
- [ ] Test expiration timer countdown

### Phase 3: Client-Side Encryption
- [ ] Implement AES-256-GCM encryption/decryption
- [ ] Implement PBKDF2 key derivation
- [ ] Create encryption service
- [ ] Add encryption to secret creation flow
- [ ] Add decryption to secret viewing

### Phase 4: Audit & Compliance
- [ ] Implement audit log hash chain
- [ ] Add log integrity verification
- [ ] Create audit log dashboard (admin only)
- [ ] Set up log retention policy
- [ ] Generate HIPAA compliance report

---

## Detailed Implementation Steps

### 1. Database Setup

**Status**: Migration file created at `app/migrations/002_add_e2e_encryption.sql`

Steps to deploy:
```bash
# Connect to PostgreSQL
psql -U admin -d keypouch -h localhost -p 5432

# Execute migration
\i app/migrations/002_add_e2e_encryption.sql

# Verify
SELECT COUNT(*) FROM shared_secrets;
SELECT COUNT(*) FROM audit_logs WHERE details IS NOT NULL;
```

### 2. Backend API Endpoints

**File**: `backend/security-endpoints.js` (ready for integration)

Endpoints implemented:
```
POST   /api/secrets/:id/share              Create share link
GET    /api/shared-secrets/:token          Access shared secret
GET    /api/secrets/:id/shares             List share links
DELETE /api/secrets/:id/shares/:shareId    Revoke share
POST   /api/secrets/:id/audit-log          Log secret action
GET    /api/audit-logs                     Get audit logs (admin)
GET    /api/audit-logs/:logId/verify       Verify log integrity
```

**Next Step**: Integrate `security-endpoints.js` into `backend/server.js`

### 3. Frontend UI Components

Components created:
- `web/components/ShareModal.tsx` - Share dialog with expiration timer
- `web/components/SecretActions.tsx` - Action buttons (share, view, copy, edit, delete)
- Updated `web/services/secretService.ts` - API client methods

**Next Step**: Integrate into `web/pages/Secrets.tsx`

Example integration:
```tsx
import SecretActions from '../components/SecretActions';
import ShareModal from '../components/ShareModal';

// In your secret card render:
<SecretActions
  secretId={secret.id}
  secretTitle={secret.title}
  secretContent={decryptedContent}
  userRole={userRole}
  onEdit={() => openEditModal(secret)}
  onDelete={() => openDeleteModal(secret)}
  onRefresh={() => fetchSecrets()}
/>
```

### 4. Client-Side Encryption Service

**To be created**: `web/services/encryptionService.ts`

```typescript
// Key functions needed
export async function deriveEncryptionKey(password: string, salt: Uint8Array): Promise<CryptoKey>
export async function encryptSecret(plaintext: string, key: CryptoKey): Promise<EncryptedData>
export async function decryptSecret(encrypted: string, iv: string, key: CryptoKey): Promise<string>
export function generateRandomSalt(): Uint8Array
```

### 5. JWT Token Setup for RS256

**Configuration needed in `backend/server.js`**:

```javascript
const crypto = require('crypto');
const fs = require('fs');

// Generate RSA key pair (run once, store securely)
// RSA 2048-bit keys
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});

// Store in secure location:
// - Private key: `/secrets/rsa_private.pem` (mounted at runtime, never in git)
// - Public key: Can be public, used for signature verification

const RS_PRIVATE_KEY = fs.readFileSync('/secrets/rsa_private.pem', 'utf-8');
const RS_PUBLIC_KEY = fs.readFileSync('/secrets/rsa_public.pem', 'utf-8');
```

### 6. Testing Checklist

**Security Tests**:
- [ ] **Token Tampering**: Modify JWT, verify rejection
  ```bash
  curl -X GET "http://localhost:3002/api/shared-secrets/MODIFIED_TOKEN"
  Expected: 401 Unauthorized
  ```

- [ ] **One-Time View**: Access twice, verify destroyed on 2nd access
  ```bash
  curl -X GET "http://localhost:3002/api/shared-secrets/$TOKEN"  # 1st: 200 OK
  curl -X GET "http://localhost:3002/api/shared-secrets/$TOKEN"  # 2nd: 410 Gone
  ```

- [ ] **Expiration**: Access expired share, verify 410 Gone
  ```bash
  # Create share with 1 minute expiration
  # Wait 61 seconds
  # Access should return 410 Gone + "share_expired"
  ```

- [ ] **Rate Limiting**: Submit 11 share requests in 1 minute
  ```bash
  for i in {1..15}; do
    curl -X POST "http://localhost:5001/api/secrets/1/share" ...
    # Requests 11-15 should return 429 Too Many Requests
  done
  ```

- [ ] **Key Isolation**: Verify server never stores encryption keys
  ```sql
  -- These queries should show no plaintext keys
  SELECT * FROM users WHERE password NOT LIKE '%$2a%';  -- bcrypt hashes only
  SELECT * FROM secret_encryption_keys LIMIT 1;  -- Shows salt, not key
  ```

**Compliance Tests**:
- [ ] **Audit Trail**: All actions logged with timestamp
  ```sql
  SELECT action, username, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 10;
  ```

- [ ] **HIPAA Immutability**: Hash chain unbroken
  ```sql
  SELECT id, log_hash, previous_log_hash FROM audit_logs WHERE id NOT IN (
    SELECT log_id FROM audit_log_verification WHERE is_valid = TRUE
  );
  -- Should return empty result set
  ```

---

## Security Configuration

### Environment Variables

Add to `.env`:
```dotenv
# E2E Encryption
ENCRYPTION_ALGORITHM=AES-256-GCM
KEY_DERIVATION_ITERATIONS=100000

# JWT/RS256
JWT_SECRET=your-jwt-secret-here-change-in-prod
RSA_PRIVATE_KEY_PATH=/secrets/rsa_private.pem
RSA_PUBLIC_KEY_PATH=/secrets/rsa_public.pem

# Audit & Compliance
AUDIT_LOG_RETENTION_DAYS=2190  # 6 years for HIPAA
ENABLE_IMMUTABLE_LOGS=true
ENABLE_HASH_CHAIN_VERIFICATION=true

# Share Configuration
SHARE_MAX_VIEWS_DEFAULT=1
SHARE_EXPIRATION_DEFAULT_MINUTES=1440
SHARE_RATE_LIMIT_PER_MINUTE=10

# Client-Side
REACT_APP_SHARE_CLIPBOARD_TIMEOUT_SECONDS=60
```

### Docker Security

In `docker-compose.yml`:
```yaml
services:
  backend:
    volumes:
      - /secrets/rsa_private.pem:/secrets/rsa_private.pem:ro
      - /secrets/rsa_public.pem:/secrets/rsa_public.pem:ro
    environment:
      - RSA_PRIVATE_KEY_PATH=/secrets/rsa_private.pem
      - RSA_PUBLIC_KEY_PATH=/secrets/rsa_public.pem
```

### Kubernetes Security

Deploy RSA keys as Kubernetes secrets:
```bash
kubectl create secret generic rsa-keys \
  --from-file=private.pem=/path/to/rsa_private.pem \
  --from-file=public.pem=/path/to/rsa_public.pem \
  -n keypouch
```

---

## API Response Examples

### Create Share Link
```bash
curl -X POST http://localhost:5001/api/secrets/1/share \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "expiresInMinutes": 1440,
    "maxViews": 1,
    "allowedEmails": ["recipient@company.com"]
  }'

# Response:
{
  "shareUrl": "http://localhost:3002/share/eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresAt": "2026-02-10T05:30:00Z",
  "createdAt": "2026-02-09T05:30:00Z",
  "maxViews": 1,
  "viewsRemaining": 1
}
```

### Access Shared Secret (Success)
```bash
curl -X GET http://localhost:5001/api/shared-secrets/eyJhbGc...

# Response:
{
  "id": "jti_abc123",
  "secretId": 1,
  "title": "AWS Production API Key",
  "category": "api_key",
  "encryptedContent": "U2FsdGVkX1...",
  "iv": "base64_encoded_iv",
  "authTag": "base64_encoded_auth_tag",
  "username": "admin",
  "url": "https://api.aws.amazon.com",
  "sharedAt": "2026-02-09T05:30:00Z",
  "expiresAt": "2026-02-10T05:30:00Z",
  "viewsRemaining": 0,
  "sharedBy": "User"
}
```

### Access Shared Secret (One-Time View Already Accessed)
```bash
# Second access to same share
curl -X GET http://localhost:5001/api/shared-secrets/eyJhbGc...

# Response (410 Gone):
{
  "error": "shared_secret_accessed",
  "message": "This shared secret was already viewed and destroyed",
  "destroyedAt": "2026-02-09T05:35:42.123Z"
}
```

---

## Troubleshooting

### Share Link Not Working
1. Check token expiration: `Date.now() > expiresAt`
2. Verify signature: Check RS256 key pair exists
3. Look in audit logs: `SELECT * FROM share_access_logs WHERE share_id = '...'`

### Clipboard Not Clearing
1. Check browser Clipboard API support (modern browsers only)
2. Verify not in private/incognito mode (some browsers restrict)
3. Check console for security errors
4. Timeout might not fire if page closed - this is expected

### One-Time View Not Destroying
1. Check if `max_views = 1` on share creation
2. Verify atomicity: Only one increments views_count
3. Look for race condition: Check `share_access_logs` for concurrent attempts
4. Verify `destroyed_at` timestamp is set: `SELECT destroyed_at FROM shared_secrets WHERE id = '...'`

### Audit Log Hash Chain Broken
1. Verify `log_hash` matches SHA-256 of log entry
2. Check `previous_log_hash` points to correct previous entry
3. Use `/api/audit-logs/:logId/verify` to detect tampering
4. Re-verify entire chain if any log modified

---

## Monitoring & Metrics

### Key Metrics to Monitor
```sql
-- Daily share creations
SELECT DATE_TRUNC('day', created_at) as day, COUNT(*) as shares
FROM shared_secrets
GROUP BY day ORDER BY day DESC;

-- Most shared secrets (by category)
SELECT s.category, COUNT(DISTINCT ss.id) as share_count
FROM shared_secrets ss
JOIN secrets s ON ss.secret_id = s.id
GROUP BY s.category
ORDER BY share_count DESC;

-- One-time views accessed
SELECT COUNT(*) as one_time_accesses_total
FROM shared_secrets
WHERE destroyed_at IS NOT NULL;

-- Audit log by action
SELECT action, COUNT(*) as count
FROM audit_logs
WHERE timestamp > NOW() - INTERVAL '7 days'
GROUP BY action
ORDER BY count DESC;
```

### Alerts to Set Up
- ⚠️ Share rate limit exceeded: `SELECT COUNT(*) FROM shared_secrets WHERE created_by = $1 AND created_at > NOW() - INTERVAL '1 minute' > 10`
- ⚠️ Failed access attempts: `SELECT COUNT(*) FROM share_access_logs WHERE access_status = 'failed' AND accessed_at > NOW() - INTERVAL '1 hour'`
- ⚠️ Audit log hash chain broken: `SELECT COUNT(DISTINCT log_id) FROM audit_log_verification WHERE is_valid = FALSE`

---

## References

- SECURITY_ARCHITECTURE.md - Full technical specification
- RFC 7518 - JSON Web Signature (RS256)
- RFC 2898 - PBKDF2
- NIST SP 800-38D - GCM Mode
- 45 CFR § 164.312(b) - HIPAA Audit Controls

---

**Last Updated**: February 9, 2026  
**Implementation Status**: Phase 2 (Frontend Components Complete)  
**Next Phase**: Client-side encryption & JWT integration
