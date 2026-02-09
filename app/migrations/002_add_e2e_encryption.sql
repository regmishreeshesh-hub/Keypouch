-- Migration: Add End-to-End Encryption Support & Shared Secrets
-- Date: February 9, 2026
-- Version: 002

-- ============================================================================
-- 1. Enhance secrets table for encrypted content storage
-- ============================================================================
ALTER TABLE secrets
ADD COLUMN IF NOT EXISTS encrypted_content TEXT,
ADD COLUMN IF NOT EXISTS content_iv VARCHAR(255),
ADD COLUMN IF NOT EXISTS content_auth_tag VARCHAR(255),
ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1,
ADD COLUMN IF NOT EXISTS previous_version_id INTEGER REFERENCES secrets(id),
ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP NULL,
ADD COLUMN IF NOT EXISTS encryption_algorithm VARCHAR(20) DEFAULT 'AES-256-GCM',
ADD COLUMN IF NOT EXISTS key_derivation_version INTEGER DEFAULT 1;

-- ============================================================================
-- 2. Create shared_secrets table for secure secret sharing
-- ============================================================================
CREATE TABLE IF NOT EXISTS shared_secrets (
    id VARCHAR(63) PRIMARY KEY,
    secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    created_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Share constraints
    max_views INTEGER DEFAULT 1,
    views_count INTEGER DEFAULT 0,
    viewed_at TIMESTAMP NULL,
    viewed_by_ip VARCHAR(45) NULL,
    
    -- Expiration
    expires_at TIMESTAMP NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP NULL,
    
    -- Access control (optional)
    allowed_emails TEXT[] NULL,
    require_password BOOLEAN DEFAULT FALSE,
    password_hash VARCHAR(255) NULL,
    
    -- Audit & Verification
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    destroyed_at TIMESTAMP NULL,
    destruction_hash VARCHAR(64) NULL,
    
    -- Constraints
    CONSTRAINT valid_views CHECK (views_count <= COALESCE(max_views, 999999))
);

CREATE INDEX IF NOT EXISTS idx_shared_secrets_secret_id 
ON shared_secrets(secret_id);
CREATE INDEX IF NOT EXISTS idx_shared_secrets_created_by 
ON shared_secrets(created_by);
CREATE INDEX IF NOT EXISTS idx_shared_secrets_expires_at 
ON shared_secrets(expires_at);
CREATE INDEX IF NOT EXISTS idx_shared_secrets_destroyed_at 
ON shared_secrets(destroyed_at);
CREATE INDEX IF NOT EXISTS idx_shared_secrets_active 
ON shared_secrets(is_revoked, expires_at) WHERE is_revoked = FALSE AND destroyed_at IS NULL;

-- ============================================================================
-- 3. Enhance audit_logs table for HIPAA compliance & immutability
-- ============================================================================
ALTER TABLE audit_logs
ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS resource_type VARCHAR(50),
ADD COLUMN IF NOT EXISTS resource_id VARCHAR(100),
ADD COLUMN IF NOT EXISTS details JSONB,
ADD COLUMN IF NOT EXISTS user_agent TEXT,
ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'success',
ADD COLUMN IF NOT EXISTS error_message TEXT,
ADD COLUMN IF NOT EXISTS transaction_id VARCHAR(100),
ADD COLUMN IF NOT EXISTS log_hash VARCHAR(64),
ADD COLUMN IF NOT EXISTS previous_log_hash VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id 
ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource 
ON audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action 
ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_transaction 
ON audit_logs(transaction_id);

-- Hash chain for immutability - ensure each log entry chain is valid
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_hash_chain 
ON audit_logs(previous_log_hash) WHERE previous_log_hash IS NOT NULL;

-- ============================================================================
-- 4. Create share_access_logs table for tracking share access attempts
-- ============================================================================
CREATE TABLE IF NOT EXISTS share_access_logs (
    id SERIAL PRIMARY KEY,
    share_id VARCHAR(63) NOT NULL REFERENCES shared_secrets(id) ON DELETE CASCADE,
    accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    accessed_from_ip VARCHAR(45),
    user_agent TEXT,
    access_status VARCHAR(20),  -- 'success', 'expired', 'not_found', 'limit_exceeded'
    status_reason TEXT,
    
    -- For debugging access issues
    view_number INTEGER,
    max_views_allowed INTEGER
);

CREATE INDEX IF NOT EXISTS idx_share_access_logs_share_id 
ON share_access_logs(share_id);
CREATE INDEX IF NOT EXISTS idx_share_access_logs_accessed_at 
ON share_access_logs(accessed_at DESC);

-- ============================================================================
-- 5. Create audit_log_verification table for hash chain validation
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_log_verification (
    id SERIAL PRIMARY KEY,
    log_id INTEGER NOT NULL REFERENCES audit_logs(id) ON DELETE CASCADE,
    verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_valid BOOLEAN,
    verification_details JSONB,
    verified_by VARCHAR(100),  -- 'system', 'admin', or user
    
    UNIQUE(log_id)
);

CREATE INDEX IF NOT EXISTS idx_audit_log_verification_log_id 
ON audit_log_verification(log_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_verification_is_valid 
ON audit_log_verification(is_valid, verified_at DESC);

-- ============================================================================
-- 6. Create secret_encryption_keys table for key management
-- ============================================================================
CREATE TABLE IF NOT EXISTS secret_encryption_keys (
    id SERIAL PRIMARY KEY,
    secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Key derivation parameters (salt, iterations, hash algorithm)
    key_salt VARCHAR(255) NOT NULL,  -- base64 encoded 16-byte salt
    key_derivation_algorithm VARCHAR(50) DEFAULT 'PBKDF2-SHA256',
    key_derivation_iterations INTEGER DEFAULT 100000,
    
    -- Key verification without storing the actual key
    key_verification_hash VARCHAR(64),  -- HMAC-SHA256 for verification
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    rotated_at TIMESTAMP NULL,
    
    -- Track which version of the key is active
    is_active BOOLEAN DEFAULT TRUE,
    version INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_secret_encryption_keys_secret_id 
ON secret_encryption_keys(secret_id);
CREATE INDEX IF NOT EXISTS idx_secret_encryption_keys_user_id 
ON secret_encryption_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_secret_encryption_keys_active 
ON secret_encryption_keys(secret_id, is_active) WHERE is_active = TRUE;

-- ============================================================================
-- 7. Grant appropriate column-level security if using RLS
-- ============================================================================
-- Row-Level Security for shared_secrets (optional)
ALTER TABLE shared_secrets ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS shared_secrets_isolation ON shared_secrets
    USING (
        created_by = current_user_id() OR 
        EXISTS (
            SELECT 1 FROM secrets 
            WHERE secrets.id = shared_secrets.secret_id 
            AND secrets.user_id = current_user_id()
        )
    );

-- ============================================================================
-- Migration Complete
-- ============================================================================
-- Verification checks:
-- SELECT COUNT(*) FROM shared_secrets;
-- SELECT COUNT(*) FROM audit_logs WHERE details IS NOT NULL;
-- SELECT COUNT(*) FROM secret_encryption_keys;
