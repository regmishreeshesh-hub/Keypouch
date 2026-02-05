import { API_BASE_URL, request, getHeaders } from './api';
import { AuthResponse, User, AuditLog } from '../types';

export const login = async (username: string, password: string): Promise<AuthResponse> => {
  try {
    return await request(`${API_BASE_URL}/login`, {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
  } catch (error: any) {
    throw new Error(error.error || 'Login failed');
  }
};

export const register = async (username: string, password: string, securityQuestion: string, securityAnswer: string): Promise<AuthResponse> => {
  try {
    return await request(`${API_BASE_URL}/register`, {
      method: 'POST',
      body: JSON.stringify({ username, password, securityQuestion, securityAnswer }),
    });
  } catch (error: any) {
    throw new Error(error.error || 'Registration failed');
  }
};

export const getSecurityQuestion = async (username: string): Promise<{ question: string }> => {
    try {
        return await request(`${API_BASE_URL}/auth/security-question?username=${encodeURIComponent(username)}`, {
            method: 'GET'
        });
    } catch (error: any) {
        throw new Error(error.error || 'User not found or no security question set');
    }
};

export const verifySecurityAnswer = async (username: string, answer: string): Promise<{ message: string, token: string }> => {
    try {
        return await request(`${API_BASE_URL}/auth/verify-security-answer`, {
            method: 'POST',
            body: JSON.stringify({ username, answer })
        });
    } catch (error: any) {
        throw new Error(error.error || 'Verification failed');
    }
};

export const requestPasswordReset = async (username: string): Promise<{ message: string; token?: string }> => {
  try {
    return await request(`${API_BASE_URL}/request-password-reset`, {
        method: 'POST',
        body: JSON.stringify({ username })
    });
  } catch (error: any) {
    throw new Error(error.error || 'Request failed');
  }
};

export const resetPassword = async (token: string, newPassword: string): Promise<{ message: string }> => {
    try {
        return await request(`${API_BASE_URL}/reset-password`, {
            method: 'POST',
            body: JSON.stringify({ token, newPassword })
        });
    } catch (error: any) {
        throw new Error(error.error || 'Reset failed');
    }
}

export const changeMyPassword = async (payload: { new_password: string; current_password?: string }): Promise<{ message: string; token: string }> => {
  try {
    return await request(`${API_BASE_URL}/me/change-password`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
  } catch (error: any) {
    throw new Error(error.error || 'Change password failed');
  }
};

// User Management Services

export const getUsers = async (): Promise<User[]> => {
  return request(`${API_BASE_URL}/users`, {
    headers: getHeaders(),
  });
};

export const updateUser = async (
  id: number,
  patch: { role?: User['role']; is_disabled?: boolean; must_reset_password?: boolean }
): Promise<{ message: string; user: User }> => {
  return request(`${API_BASE_URL}/users/${id}`, {
    method: 'PATCH',
    headers: getHeaders(),
    body: JSON.stringify(patch),
  });
};

export const updateUserRole = async (id: number, role: 'admin' | 'full-access' | 'modify' | 'view'): Promise<void> => {
  return request(`${API_BASE_URL}/users/${id}`, {
    method: 'PUT',
    headers: getHeaders(),
    body: JSON.stringify({ role }),
  });
};

export const deleteUser = async (id: number): Promise<void> => {
  return request(`${API_BASE_URL}/users/${id}`, {
    method: 'DELETE',
    headers: getHeaders(),
  });
};

export const createUser = async (payload: { username: string; password: string; role?: 'admin' | 'full-access' | 'modify' | 'view'; is_disabled?: boolean; must_reset_password?: boolean }): Promise<{ message: string; user: User }> => {
  return request(`${API_BASE_URL}/users`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify(payload),
  });
};

export const updateUserStatus = async (id: number, is_disabled: boolean): Promise<{ message: string; user: User }> => {
  return request(`${API_BASE_URL}/users/${id}/status`, {
    method: 'PATCH',
    headers: getHeaders(),
    body: JSON.stringify({ is_disabled }),
  });
};

export const resetUserPassword = async (id: number, new_password: string): Promise<{ message: string; user: { id: number; username: string } }> => {
  return request(`${API_BASE_URL}/users/${id}/reset-password`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ new_password }),
  });
};

export const revokeUserSessions = async (id: number): Promise<{ message: string; user: { id: number; username: string } }> => {
  return request(`${API_BASE_URL}/users/${id}/revoke-sessions`, {
    method: 'POST',
    headers: getHeaders(),
  });
};

export const resetUserMfa = async (id: number): Promise<{ message: string; user: { id: number; username: string } }> => {
  return request(`${API_BASE_URL}/users/${id}/reset-mfa`, {
    method: 'POST',
    headers: getHeaders(),
  });
};

export const getUserDetails = async (id: number): Promise<User> => {
  return request(`${API_BASE_URL}/users/${id}`, {
    headers: getHeaders(),
  });
};

export const getUserAuditLogs = async (id: number): Promise<AuditLog[]> => {
  return request(`${API_BASE_URL}/users/${id}/audit-logs`, {
    headers: getHeaders(),
  });
};
