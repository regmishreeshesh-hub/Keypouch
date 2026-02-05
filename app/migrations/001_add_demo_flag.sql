-- Add is_demo column to distinguish demo users from real users
ALTER TABLE users ADD COLUMN is_demo BOOLEAN NOT NULL DEFAULT FALSE;

-- Mark the current admin user as demo
UPDATE users SET is_demo = TRUE WHERE username = 'admin';

-- Mark sample users as demo
UPDATE users SET is_demo = TRUE WHERE username IN ('viewuser', 'modifyuser', 'fulluser');

-- Add unique constraint for real admin users (only one real admin per system)
-- This ensures only one real admin can exist at a time
CREATE UNIQUE INDEX idx_real_admin ON users (role) WHERE role = 'admin' AND is_demo = FALSE;
