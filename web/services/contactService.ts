import { API_BASE_URL, getHeaders, request } from './api';
import { Contact, ContactPayload } from '../types';

export const getContacts = async (search?: string): Promise<Contact[]> => {
  const query = search ? `?search=${encodeURIComponent(search)}` : '';
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

// For the export URL, we can't easily mock a blob download via a simple string URL in this architecture without a real backend.
// We will mock the behavior in the component if needed, but for now we keep the constant.
export const exportContactsUrl = `${API_BASE_URL}/contacts/export`;