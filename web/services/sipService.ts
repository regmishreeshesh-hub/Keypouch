import { API_BASE_URL, getHeaders, request } from './api';
import { SipAccount, SipAccountPayload } from '../types';

export const getSipAccounts = async (): Promise<SipAccount[]> => {
  return request(`${API_BASE_URL}/sip-accounts`, {
    headers: getHeaders(),
  });
};

export const createSipAccount = async (payload: SipAccountPayload): Promise<SipAccount> => {
  return request(`${API_BASE_URL}/sip-accounts`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify(payload),
  });
};

export const updateSipAccount = async (id: number, payload: SipAccountPayload): Promise<SipAccount> => {
  return request(`${API_BASE_URL}/sip-accounts/${id}`, {
    method: 'PUT',
    headers: getHeaders(),
    body: JSON.stringify(payload),
  });
};

export const deleteSipAccount = async (id: number): Promise<{ message: string }> => {
  return request(`${API_BASE_URL}/sip-accounts/${id}`, {
    method: 'DELETE',
    headers: getHeaders(),
  });
};
