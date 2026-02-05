import { API_BASE_URL, getHeaders, request } from './api';
import { AuditLog } from '../types';

export const getAuditLogs = async (): Promise<AuditLog[]> => {
  return request(`${API_BASE_URL}/audit-logs`, {
    headers: getHeaders(),
  });
};