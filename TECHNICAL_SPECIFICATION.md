# Technical Specification: KeyPouch Secure Secrets Management System

## 1. System Architecture
KeyPouch follows a **Zero-Knowledge Architecture** with **End-to-End Encryption (E2EE)** using **AES-256-GCM**.

### 1.1 Core Principles
- **Client-Side Encryption**: All sensitive data is encrypted/decrypted on the client side.
- **Server Ignorance**: The server stores only encrypted payloads and metadata. It never sees or stores plaintext secrets or encryption keys.
- **Key Derivation**: Encryption keys are derived from user passwords using PBKDF2-SHA256 with 100,000 iterations.
- **One-Time View**: Shared secrets are cryptographically destroyed immediately after the first successful access.

## 2. Security Mechanisms

### 2.1 Encryption Standards
- **Algorithm**: AES-256-GCM (Galois/Counter Mode) for authenticated encryption.
- **IV/Nonce**: 12-byte cryptographically random initialization vector for each encryption.
- **Authentication Tag**: GCM provides a 16-byte authentication tag to ensure integrity.

### 2.2 Shared Secret Destruction
- **Process**: Upon the first access request, the server:
  1. Validates the RS256 signed share token.
  2. Increments the view count.
  3. Checks if `max_views` (default 1) is reached.
  4. If reached, marks the record as `destroyed_at` and computes a destruction hash.
  5. Returns the encrypted payload to the client.
  6. Subsequent requests return `410 Gone`.
- **Verification**: Destruction is logged with a verification hash: `HMAC-SHA256(share_id + destruction_timestamp)`.

## 3. API Endpoints (JWT Authenticated)

### 3.1 Secrets Management
- `GET /api/secrets`: List secrets (returns metadata + encrypted payload).
- `POST /api/secrets`: Create a new secret (client sends encrypted payload).
- `PUT /api/secrets/:id`: Update a secret.
- `DELETE /api/secrets/:id`: (Soft) delete a secret and revoke all shares.

### 3.2 Sharing
- `POST /api/secrets/:id/share`: Generate an E2EE share link.
- `GET /api/shared-secrets/:token`: Access a shared secret (one-time view).

## 4. UI/UX Specifications

### 4.1 Sharing Modal
- **Expiration Timer**: Real-time countdown for custom expiration.
- **One-Time View Toggle**: Force destruction after first access.
- **Direct Copy**: Button to copy the generated share link.

### 4.2 Inline Actions (List View)
- `Share`: Opens sharing modal.
- `Edit`: Encrypted edit flow.
- `View`: Decrypt and display secret.
- `Copy`: Secure copy-to-clipboard with 60s auto-clear.
- `Delete`: Permanent removal with confirmation.

## 5. Audit Logging (HIPAA Compliant)
All user actions are logged with:
- **Timestamp**: Immutable UTC timestamp.
- **Action**: e.g., `SECRET_SHARED`, `SECRET_COPIED`, `SHARED_SECRET_DESTROYED`.
- **IP Address**: Source of the request.
- **Transaction ID**: Unique identifier for cross-referencing logs.
- **Immutability**: Logs are linked via a hash chain (`previous_log_hash`).
