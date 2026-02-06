export interface User {
  id: number;
  username: string;
  role: 'admin' | 'full-access' | 'modify' | 'view';
  created_at?: string;
  is_disabled?: boolean;
  must_reset_password?: boolean;
  mfa_enabled?: boolean;
  session_version?: number;
  is_demo?: boolean;
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
  is_demo?: boolean;
  error?: string;
}

export interface Contact {
  id: number;
  name: string;
  phone: string;
  address?: string;
  created_at?: string;
  isFavorite?: boolean;
  emergencyContacts?: EmergencyContact[];
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
  user_id?: number;
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
  emergencyContacts?: Array<{
    name: string;
    phone: string;
    email: string;
    relationship: RelationshipType;
  }>;
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

export type SipServerType = 'grandstream' | 'asterisk' | 'freepbx' | 'generic';
export type SipTransport = 'udp' | 'tcp' | 'tls' | 'wss';

export interface SipAccount {
  id: number;
  label?: string | null;
  server_type: SipServerType;
  server_host: string;
  server_port: number;
  username: string;
  extension?: string | null;
  transport: SipTransport;
  ws_path?: string | null;
  created_at?: string;
}

export interface SipAccountPayload {
  label?: string | null;
  server_type: SipServerType;
  server_host: string;
  server_port?: number;
  username: string;
  password?: string;
  extension?: string | null;
  transport?: SipTransport;
  ws_path?: string | null;
}

export interface CallLog {
  id: number;
  user_id: number;
  contact_id: number;
  sip_account_id?: number | null;
  phone_number?: string | null;
  direction: 'outbound' | 'inbound';
  status: 'completed' | 'failed' | 'canceled' | 'busy' | 'no_answer';
  duration_seconds?: number;
  started_at: string;
  ended_at?: string | null;
  created_at?: string;
}

export type PhoneType = 'work' | 'home' | 'cell';

export type RelationshipType = 'spouse' | 'parent' | 'friend' | 'sibling' | 'doctor' | 'lawyer' | 'other';

export interface PhoneNumber {
  type: PhoneType;
  number: string;
}

export interface EmergencyContact {
  id: number;
  name: string;
  phone: string;
  email: string;
  relationship: RelationshipType;
}

export interface EmployeeContact {
  id: string;
  name: string;
  email: string;
  role: string;
  address?: string;
  phones: PhoneNumber[];
  emergencyContacts: EmergencyContact[];
}
