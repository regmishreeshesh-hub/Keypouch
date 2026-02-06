import { API_BASE_URL, getHeaders, request } from './api';
import { Contact, ContactPayload, EmergencyContact } from '../types';

export const getContacts = async (search?: string, page?: number, limit?: number): Promise<Contact[]> => {
  const params = new URLSearchParams();
  if (search) params.append('search', search);
  if (page) params.append('page', page.toString());
  if (limit) params.append('limit', limit.toString());
  
  const query = params.toString() ? `?${params}` : '';
  return request(`${API_BASE_URL}/contacts${query}`, {
    headers: getHeaders(),
  });
};

export const createContact = async (data: ContactPayload): Promise<{ message: string }> => {
  return request(`${API_BASE_URL}/contacts`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify(data),
  });
};

export const updateContact = async (id: number, data: ContactPayload): Promise<{ message: string }> => {
  return request(`${API_BASE_URL}/contacts/${id}`, {
    method: 'PUT',
    headers: getHeaders(),
    body: JSON.stringify(data),
  });
};

export const deleteContact = async (id: number): Promise<{ message: string }> => {
  return request(`${API_BASE_URL}/contacts/${id}`, {
    method: 'DELETE',
    headers: getHeaders(),
  });
};

export const addEmergencyContact = async (
  contactId: number,
  payload: Omit<EmergencyContact, 'id'>
): Promise<EmergencyContact> => {
  return request(`${API_BASE_URL}/contacts/${contactId}/emergency-contacts`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify(payload),
  });
};

export const updateEmergencyContact = async (
  contactId: number,
  emergencyContactId: number,
  payload: Omit<EmergencyContact, 'id'>
): Promise<EmergencyContact> => {
  return request(`${API_BASE_URL}/contacts/${contactId}/emergency-contacts/${emergencyContactId}`, {
    method: 'PUT',
    headers: getHeaders(),
    body: JSON.stringify(payload),
  });
};

export const deleteEmergencyContact = async (
  contactId: number,
  emergencyContactId: number
): Promise<{ message: string }> => {
  return request(`${API_BASE_URL}/contacts/${contactId}/emergency-contacts/${emergencyContactId}`, {
    method: 'DELETE',
    headers: getHeaders(),
  });
};

// For the export URL, we can't easily mock a blob download via a simple string URL in this architecture without a real backend.
// We will mock the behavior in the component if needed, but for now we keep the constant.
export const exportContactsUrl = `${API_BASE_URL}/contacts/export`;
