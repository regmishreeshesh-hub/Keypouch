import { API_BASE_URL, getHeaders, request } from './api';
import { CallLog } from '../types';

export const getCallLogsForContact = async (contactId: number): Promise<CallLog[]> => {
  return request(`${API_BASE_URL}/contacts/${contactId}/call-logs`, {
    headers: getHeaders(),
  });
};

export const createCallLog = async (payload: Omit<CallLog, 'id' | 'user_id' | 'created_at'>): Promise<CallLog> => {
  return request(`${API_BASE_URL}/call-logs`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify(payload),
  });
};
