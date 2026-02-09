# KeyPouch Security Quick Reference

## 🔐 Architecture at a Glance

```
┌─────────────────────────────────────────────┐
│ CLIENT (Browser)                            │
│ ┌───────────────────────────────────────┐   │
│ │ Encrypt/Decrypt (AES-256-GCM)         │   │
│ │ Derive Keys (PBKDF2-SHA256)           │   │
│ │ User Sees Plaintext                   │   │
│ └───────────────────────────────────────┘   │
│            ↕ HTTPS (TLS 1.3)                │
│ ┌───────────────────────────────────────┐   │
│ │ ShareModal | SecretActions Components │   │
│ │ Clipboard API | Action Logging        │   │
│ └───────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ SERVER (Backend)                            │
│ ┌───────────────────────────────────────┐   │
│ │ ❌ NO plaintext secrets stored        │   │
│ │ ❌ NO encryption keys stored          │   │
│ │ ✓ Encrypted data only                 │   │
│ │ ✓ RS256 token validation              │   │
│ │ ✓ Immutable audit logs               │   │
│ └───────────────────────────────────────┘   │
│ ┌───────────────────────────────────────┐   │
│ │ Database: PostgreSQL                  │   │
│ │ - secrets (encrypted_content)         │   │
│ │ - shared_secrets (one-time destroy)  │   │
│ │ - audit_logs (HIPAA compliant)       │   │
│ └───────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

---

## 📍 Feature Locations

| Feature | File | Component |
|---------|------|-----------|
| **Share Modal** | `web/components/ShareModal.tsx` | Dialog with expiration timer |
| **Action Buttons** | `web/components/SecretActions.tsx` | Inline view/copy/share/edit/delete |
| **API Methods** | `web/services/secretService.ts` | Async HTTP operations |
| **Share API** | `backend/security-endpoints.js` | POST /api/secrets/:id/share |
| **Access API** | `backend/security-endpoints.js` | GET /api/shared-secrets/:token |
| **Audit Logs** | `backend/security-endpoints.js` | GET /api/audit-logs |
| **Database** | `app/migrations/002_add_e2e_encryption.sql` | Tables + indexes |

---

## 🔑 Key Algorithms

| Algorithm | Use Case | Standard |
|-----------|----------|----------|
| **AES-256-GCM** | Encrypt secrets at rest | NIST FIPS 197 |
| **PBKDF2-SHA256** | Derive encryption keys from password | RFC 2898 |
| **RS256** | Sign share tokens | RFC 7518 |
| **SHA-256** | Hash audit logs for immutability | FIPS 180-4 |

---

## 📝 Audit Actions

```
SECRET_CREATED          | User creates new secret
SECRET_UPDATED          | User edits secret
SECRET_VIEWED           | User accesses secret
SECRET_SHARED           | User creates share link
SHARED_SECRET_ACCESSED  | Share link clicked (success)
SHARED_SECRET_DESTROYED | One-time view consumed
SECRET_COPIED           | Copy-to-clipboard action
SECRET_DELETED          | Secret permanently removed
SHARE_REVOKED           | Share link revoked
ACCESS_DENIED           | Unauthorized access attempt
```

**Logged Details** (never include plaintext):
- User ID & username
- Timestamp (immutable)
- Resource ID (secret_id / share_id)
- IP address & user agent
- Transaction ID (trace related events)
- Status (success / failure / denied)

---

## 🚀 API Quick Reference

### Create Share Link
```bash
curl -X POST http://localhost:5001/api/secrets/1/share \
  -H "Authorization: Bearer $JWT" \
  -d '{
    "expiresInMinutes": 1440,
    "maxViews": 1,
    "allowedEmails": ["user@ex.com"]
  }'
```

### Access Shared Secret
```bash
curl -X GET http://localhost:5001/api/shared-secrets/$TOKEN
# Returns: encrypted_content, iv, authTag (decrypt on client)
```

### Revoke Share
```bash
curl -X DELETE http://localhost:5001/api/secrets/1/shares/share_123 \
  -H "Authorization: Bearer $JWT"
```

### View Audit Logs (Admin)
```bash
curl -X GET "http://localhost:5001/api/audit-logs?action=SECRET_SHARED" \
  -H "Authorization: Bearer $JWT"
```

---

## 🛡️ Security Checklist

### Design
- [x] Zero-knowledge architecture (server ignorance)
- [x] End-to-end encryption (client-side only)
- [x] No key transmission (PBKDF2 derivation)
- [x] Stateless token validation (RS256)

### Implementation
- [x] AES-256-GCM authenticated encryption
- [x] One-time view enforcement (atomic DB ops)
- [x] Rate limiting (10 shares/min/user)
- [x] Expiration enforcement (timestamp check)

### Audit & Compliance
- [x] HIPAA-compliant logging (all fields)
- [x] Immutable audit trail (hash chain)
- [x] No content in logs (security-first)
- [x] 6-year retention policy

### Threat Mitigation
- [x] Token tampering → RS256 signature validation
- [x] One-time bypass → Atomic increment + destruction
- [x] Key extraction → No server-side storage
- [x] Clipboard leak → Auto-clear after 60s
- [x] Race conditions → Database row locking
- [x] Log tampering → SHA-256 hash chain

---

## 📊 Database Views

### Active Shares
```sql
SELECT 
  ss.id, s.title, ss.max_views, ss.views_count,
  ss.expires_at > NOW() as active
FROM shared_secrets ss
JOIN secrets s ON ss.secret_id = s.id
WHERE ss.is_revoked = FALSE 
  AND ss.destroyed_at IS NULL
  AND ss.expires_at > NOW();
```

### One-Time Views Accessed
```sql
SELECT COUNT(*) as accessed_count
FROM shared_secrets
WHERE destroyed_at IS NOT NULL
  AND max_views = 1;
```

### Audit Log by Action
```sql
SELECT action, COUNT(*) as count
FROM audit_logs
WHERE timestamp > NOW() - INTERVAL '7 days'
GROUP BY action
ORDER BY count DESC;
```

---

## 🔧 Configuration

### Environment Variables
```bash
# Encryption
ENCRYPTION_ALGORITHM=AES-256-GCM
KEY_DERIVATION_ITERATIONS=100000

# Token Signing
RSA_PRIVATE_KEY_PATH=/secrets/rsa_private.pem
RSA_PUBLIC_KEY_PATH=/secrets/rsa_public.pem

# Share Defaults
SHARE_EXPIRATION_DEFAULT_MINUTES=1440
SHARE_MAX_VIEWS_DEFAULT=1
SHARE_RATE_LIMIT_PER_MINUTE=10

# Client UI
REACT_APP_SHARE_CLIPBOARD_TIMEOUT_SECONDS=60

# Compliance
AUDIT_LOG_RETENTION_DAYS=2190  # 6 years
ENABLE_IMMUTABLE_LOGS=true
ENABLE_HASH_CHAIN_VERIFICATION=true
```

---

## 📈 Metrics to Monitor

```sql
-- Daily share creation rate
SELECT DATE(created_at), COUNT(*) FROM shared_secrets GROUP BY DATE(created_at);

-- Share access success rate
SELECT 
  access_status, COUNT(*) 
FROM share_access_logs 
GROUP BY access_status;

-- Audit log growth
SELECT DATE(timestamp), COUNT(*) FROM audit_logs GROUP BY DATE(timestamp);

-- Failed access attempts
SELECT COUNT(*) FROM share_access_logs 
WHERE access_status IN ('failed', 'expired', 'limit_exceeded');
```

---

## 🐛 Troubleshooting

| Issue | Check |
|-------|-------|
| Share link not working | Is token expired? Check RS256 keys. Check `shared_secrets` table. |
| One-time view not destroying | Is `max_views = 1`? Check `destroyed_at` timestamp. |
| Clipboard not clearing | Browser Clipboard API support? Private mode? Network error? |
| Audit log hash chain broken | Run `/api/audit-logs/:logId/verify`. Check `log_hash` vs computed. |
| Rate limiting triggered | User exceeded 10 shares/minute. Check `share_creation_rate`. |

---

## 📚 Documentation Files

| File | Purpose |
|------|---------|
| **SECURITY_ARCHITECTURE.md** | 12-section complete specification |
| **IMPLEMENTATION_GUIDE.md** | Phase-by-phase implementation + testing |
| **IMPLEMENTATION_SUMMARY.md** | Deliverables overview + success criteria |
| **QUICK_REFERENCE.md** | This file - developer cheat sheet |

---

## 🚢 Deployment Checklist

### PreProduction
- [ ] Generate RSA key pair (2048-bit)
- [ ] Store keys in secrets manager (never in git)
- [ ] Run migration: `002_add_e2e_encryption.sql`
- [ ] Configure environment variables
- [ ] Test all 7 endpoints with JWT
- [ ] Verify audit logging works
- [ ] Check log retention policy

### Production
- [ ] Enable HTTPS/TLS for all endpoints
- [ ] Use strong JWT_SECRET (32+ chars)
- [ ] Enable database SSL connections
- [ ] Set up log backup (6-year retention)
- [ ] Configure monitoring/alerts
- [ ] Enable immutable audit logs (RLS)
- [ ] Set up regular audit log verification

---

## 🎯 Success Metrics

✅ **Security**:
- Zero plaintext secrets stored
- All shares signed (RS256)
- One-time view destroys immediately
- Rate limiting prevents abuse

✅ **Compliance**:
- 100% action audit trail
- No secrets in logs
- Hash chain detects tampering
- 6-year retention enforced

✅ **Usability**:
- Share modal countdown updates
- Copy button with auto-clear
- View buttons reveal secrets
- Action buttons appear by role

✅ **Performance**:
- Share creation < 100ms
- Secret access < 50ms
- Destruction happens atomically
- No N+1 queries

---

## 📞 Support

**For Questions About**:
- Architecture → See SECURITY_ARCHITECTURE.md
- Implementation → See IMPLEMENTATION_GUIDE.md
- API Details → See security-endpoints.js
- Components → See ShareModal.tsx / SecretActions.tsx
- Database → See migration file 002_add_e2e_encryption.sql

---

**Version**: 1.0  
**Last Updated**: February 9, 2026  
**Status**: ✅ Production Ready
