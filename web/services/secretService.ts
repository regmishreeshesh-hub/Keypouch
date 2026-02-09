import { API_BASE_URL, getHeaders, request } from './api';
import { Secret, SecretPayload, ShareConfig, CustomCategory } from '../types';

export const getSecrets = async (search?: string, category?: string): Promise<Secret[]> => {
  const params = new URLSearchParams();
  if (search) params.append('search', search);
  if (category) params.append('category', category);

  return request(`${API_BASE_URL}/secrets?${params.toString()}`, {
    headers: getHeaders(),
  });
};

export const getSecretDetails = async (id: number): Promise<Secret> => {
  return request(`${API_BASE_URL}/secrets/${id}`, {
    headers: getHeaders(),
  });
};

export const createSecret = async (data: SecretPayload): Promise<{ message: string }> => {
  return request(`${API_BASE_URL}/secrets`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify(data),
  });
};

export const updateSecret = async (id: number, data: SecretPayload): Promise<{ message: string }> => {
  return request(`${API_BASE_URL}/secrets/${id}`, {
    method: 'PUT',
    headers: getHeaders(),
    body: JSON.stringify(data),
  });
};

export const deleteSecret = async (id: number): Promise<{ message: string }> => {
  return request(`${API_BASE_URL}/secrets/${id}`, {
    method: 'DELETE',
    headers: getHeaders(),
  });
};

// Enhanced Share Link with E2E Encryption
export const createShareLink = async (
  id: number,
  config: {
    expiresInMinutes?: number | null;
    maxViews?: number;
    allowedEmails?: string[];
    encrypted_content?: string;
    content_iv?: string;
    content_auth_tag?: string;
    secretData?: any;  // Fallback for server-side encryption
  }
): Promise<{ token: string; expiresAt: string; maxViews: number }> => {
  return request(`${API_BASE_URL}/secrets/${id}/share`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify(config),
  });
};

export const getShareLinks = async (secretId: number): Promise<any[]> => {
  return request(`${API_BASE_URL}/secrets/${secretId}/shares`, {
    headers: getHeaders(),
  });
};

export const revokeShareLink = async (secretId: number, shareId: string): Promise<{ message: string }> => {
  return request(`${API_BASE_URL}/secrets/${secretId}/shares/${shareId}`, {
    method: 'DELETE',
    headers: getHeaders(),
  });
};

export const getSharedSecret = async (token: string): Promise<Secret> => {
  return request(`${API_BASE_URL}/shared-secrets/${token}`, {
    method: 'GET',
  });
};

// Audit Logging
export const logSecretAction = async (
  action: 'view' | 'copy' | 'share' | 'edit' | 'delete',
  secretId: number,
  details?: Record<string, any>
): Promise<{ message: string }> => {
  return request(`${API_BASE_URL}/secrets/${secretId}/audit-log`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({
      action,
      details,
    }),
  });
};

export const getSecretAuditLog = async (secretId: number): Promise<any[]> => {
  return request(`${API_BASE_URL}/secrets/${secretId}/audit-log`, {
    headers: getHeaders(),
  });
};

export const getAuditLogs = async (filters?: {
  action?: string;
  username?: string;
  startDate?: string;
  endDate?: string;
}): Promise<any[]> => {
  const params = new URLSearchParams();
  if (filters?.action) params.append('action', filters.action);
  if (filters?.username) params.append('username', filters.username);
  if (filters?.startDate) params.append('startDate', filters.startDate);
  if (filters?.endDate) params.append('endDate', filters.endDate);

  return request(`${API_BASE_URL}/audit-logs?${params.toString()}`, {
    headers: getHeaders(),
  });
};

export const verifyAuditLogIntegrity = async (logId: number): Promise<{ isValid: boolean; message: string }> => {
  return request(`${API_BASE_URL}/audit-logs/${logId}/verify`, {
    headers: getHeaders(),
  });
};

// Custom Categories
export const getCustomCategories = async (): Promise<CustomCategory[]> => {
  return request(`${API_BASE_URL}/custom-categories`, {
    headers: getHeaders(),
  });
};

export const createCustomCategory = async (label: string): Promise<CustomCategory> => {
  return request(`${API_BASE_URL}/custom-categories`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ label }),
  });
};

export const deleteCustomCategory = async (id: string): Promise<void> => {
  return request(`${API_BASE_URL}/custom-categories/${id}`, {
    method: 'DELETE',
    headers: getHeaders(),
  });
};