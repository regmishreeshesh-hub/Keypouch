import { User, Contact, Secret, AuditLog, SharedLink, CustomCategory } from '../types';

const resolveApiBaseUrl = () => {
  const envUrl = import.meta.env?.VITE_API_URL as string | undefined;
  if (envUrl) {
    // If it's a relative URL, construct the full URL using current page protocol/host
    if (envUrl.startsWith('/')) {
      const protocol = window.location?.protocol || 'https:';
      const hostname = window.location?.hostname || 'localhost';
      const port = window.location?.port || (protocol === 'https:' ? '443' : '80');
      const portPart = (protocol === 'https:' && port === '443') || (protocol === 'http:' && port === '80') ? '' : `:${port}`;
      return `${protocol}//${hostname}${portPart}${envUrl}`;
    }
    return envUrl.replace(/\/+$/, '');
  }

  // Fallback to environment variable or default
  const reactApiUrl = import.meta.env?.REACT_APP_API_URL as string | undefined;
  if (reactApiUrl) {
    // If it's a relative URL, construct the full URL using current page protocol/host
    if (reactApiUrl.startsWith('/')) {
      const protocol = window.location?.protocol || 'https:';
      const hostname = window.location?.hostname || 'localhost';
      const port = window.location?.port || (protocol === 'https:' ? '443' : '80');
      const portPart = (protocol === 'https:' && port === '443') || (protocol === 'http:' && port === '80') ? '' : `:${port}`;
      return `${protocol}//${hostname}${portPart}${reactApiUrl}`;
    }
    return reactApiUrl.replace(/\/+$/, '');
  }

  // Dynamic fallback - use current page protocol/host for flexible deployment
  const protocol = window.location?.protocol || 'https:';
  const hostname = window.location?.hostname || 'localhost';
  const port = window.location?.port || (protocol === 'https:' ? '443' : '80');
  const portPart = (protocol === 'https:' && port === '443') || (protocol === 'http:' && port === '80') ? '' : `:${port}`;
  return `${protocol}//${hostname}${portPart}/api`;
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
