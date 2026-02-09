-- KeyPouch Zero-Knowledge Migration

-- 1. Enhance Secrets Table for E2EE
ALTER TABLE secrets 
    ADD COLUMN encrypted_content TEXT,
    ADD COLUMN content_iv VARCHAR(255),
    ADD COLUMN content_auth_tag VARCHAR(255),
    ADD COLUMN version INTEGER DEFAULT 1,
    ADD COLUMN encryption_algorithm VARCHAR(20) DEFAULT 'AES-256-GCM',
    ADD COLUMN is_deleted BOOLEAN DEFAULT FALSE,
    ADD COLUMN deleted_at TIMESTAMP NULL;

-- 2. Create Shared Secrets Table
CREATE TABLE IF NOT EXISTS shared_secrets (
    id VARCHAR(63) PRIMARY KEY,  -- JTI from RS256 token
    secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    created_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Share constraints
    max_views INTEGER DEFAULT 1,
    views_count INTEGER DEFAULT 0,
    viewed_at TIMESTAMP NULL,
    viewed_by_ip VARCHAR(45) NULL,
    
    -- Expiration
    expires_at TIMESTAMP NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP NULL,
    
    -- E2EE fields for the shared content
    encrypted_content TEXT,
    content_iv VARCHAR(255),
    content_auth_tag VARCHAR(255),
    
    -- Access control
    allowed_emails TEXT NULL,  -- JSON string of whitelisted emails
    
    -- Audit & Destruction
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    destroyed_at TIMESTAMP NULL,
    destruction_hash VARCHAR(64) NULL,  -- HMAC-SHA256 verification
    
    CONSTRAINT valid_views CHECK (views_count <= max_views OR max_views IS NULL)
);

-- 3. Create Share Access Logs
CREATE TABLE IF NOT EXISTS share_access_logs (
    id SERIAL PRIMARY KEY,
    share_id VARCHAR(63) REFERENCES shared_secrets(id) ON DELETE CASCADE,
    accessed_from_ip VARCHAR(45),
    user_agent TEXT,
    access_status VARCHAR(20),
    view_number INTEGER,
    max_views_allowed INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. Enhance Audit Logs
-- (Note: audit_logs already exists, we enhance it with more fields if needed)
ALTER TABLE audit_logs 
    ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS resource_type VARCHAR(50),
    ADD COLUMN IF NOT EXISTS resource_id VARCHAR(100),
    ADD COLUMN IF NOT EXISTS status VARCHAR(20),
    ADD COLUMN IF NOT EXISTS transaction_id VARCHAR(100),
    ADD COLUMN IF NOT EXISTS log_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS previous_log_hash VARCHAR(64);

-- 5. Create Indexes for performance
CREATE INDEX IF NOT EXISTS idx_shared_secrets_secret_id ON shared_secrets(secret_id);
CREATE INDEX IF NOT EXISTS idx_shared_secrets_expires_at ON shared_secrets(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
