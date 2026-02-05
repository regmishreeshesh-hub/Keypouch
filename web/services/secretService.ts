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

export const createShareLink = async (id: number, config: ShareConfig): Promise<{ link: string, token: string }> => {
    return request(`${API_BASE_URL}/secrets/${id}/share`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(config)
    });
};

export const getSharedSecret = async (token: string): Promise<Secret> => {
    return request(`${API_BASE_URL}/shared-secrets/${token}`, {
        method: 'GET'
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
        body: JSON.stringify({ label })
    });
};

export const deleteCustomCategory = async (id: string): Promise<void> => {
    return request(`${API_BASE_URL}/custom-categories/${id}`, {
        method: 'DELETE',
        headers: getHeaders(),
    });
};