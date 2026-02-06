import { User, Contact, Secret, AuditLog, SharedLink, CustomCategory } from '../types';

const resolveApiBaseUrl = () => {
  const envUrl = import.meta.env?.VITE_API_URL as string | undefined;
  if (envUrl) {
    return envUrl.replace(/\/+$/, '');
  }

  if (typeof window !== 'undefined' && window.location) {
    const { protocol, hostname } = window.location;
    return `${protocol}//${hostname}:5001/api`;
  }

  return 'http://localhost:5001/api';
};

export const API_BASE_URL = resolveApiBaseUrl();

export const request = async (endpoint: string, options: RequestInit = {}): Promise<any> => {
  const url = endpoint.startsWith(API_BASE_URL) ? endpoint : `${API_BASE_URL}${endpoint}`;
  
  const defaultHeaders = {
    'Content-Type': 'application/json',
  };

  // Get token from localStorage for protected routes
  const token = localStorage.getItem('token');
  if (token) {
    defaultHeaders['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(url, {
    ...options,
    headers: {
      ...defaultHeaders,
      ...options.headers,
    },
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
  }

  return response.json();
};

export const getHeaders = () => {
  const token = localStorage.getItem('token');
  return {
    'Content-Type': 'application/json',
    ...(token && { Authorization: `Bearer ${token}` }),
  };
};
