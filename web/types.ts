export interface User {
  id: number;
  username: string;
  role: 'admin' | 'full-access' | 'modify' | 'view';
  created_at?: string;
  is_disabled?: boolean;
  must_reset_password?: boolean;
  mfa_enabled?: boolean;
  session_version?: number;
  last_login_at?: string | null;
  password_changed_at?: string | null;
  security_question?: string;
  security_answer?: string;
}

export interface AuthResponse {
  message: string;
  token: string;
  username: string;
  role: 'admin' | 'full-access' | 'modify' | 'view';
  must_reset_password?: boolean;
  error?: string;
}

export interface Contact {
  id: number;
  name: string;
  phone: string;
  address?: string;
  created_at?: string;
  isFavorite?: boolean;
}

export type SecretCategory = string;

export interface CustomCategory {
  id: string;
  label: string;
}

export interface Secret {
  id: number;
  title: string;
  category: SecretCategory;
  username?: string;
  password?: string;
  api_key?: string;
  url?: string;
  notes?: string;
  created_at?: string;
}

export interface SecretPayload {
  title: string;
  category: string;
  username?: string;
  password?: string;
  api_key?: string;
  url?: string;
  notes?: string;
}

export interface ContactPayload {
  name: string;
  phone: string;
  address?: string;
  isFavorite?: boolean;
}

export interface AuditLog {
  id: number;
  username: string;
  action: string;
  details: string;
  timestamp: string;
  ip: string;
}

export interface SharedLink {
  token: string;
  secretId: number;
  createdAt: string;
  expiresAt: string;
  maxViews: number;
  views: number;
  username: string;
}

export interface ShareConfig {
  expiresInMinutes: number;
  maxViews: number;
}
