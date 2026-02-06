import React, { useState, useEffect, useRef } from 'react';
import { CallLog, Contact, ContactPayload, SipAccount, SipAccountPayload } from '../types';
import * as contactService from '../services/contactService';
import * as sipService from '../services/sipService';
import * as callLogService from '../services/callLogService';
import Modal from '../components/Modal';
import { Search, Plus, Edit2, Trash2, Download, Phone, MapPin, User, Loader2, AlertTriangle, Star, Zap, Save, X, Check, Upload, Settings } from 'lucide-react';
import { canDelete as canDeleteForRole, canModify as canModifyForRole, getRole } from '../utils/permissions';
import JsSIP from 'jssip';

const Contacts: React.FC = () => {
  const role = getRole();
  const canModify = canModifyForRole(role);
  const canDelete = canDeleteForRole(role);

  const [contacts, setContacts] = useState<Contact[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [showFavorites, setShowFavorites] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [currentContact, setCurrentContact] = useState<Partial<Contact>>({});
  const [error, setError] = useState('');

  // Import Modal State
  const [isImportModalOpen, setIsImportModalOpen] = useState(false);
  const [importProgress, setImportProgress] = useState<{
    isImporting: boolean;
    current: number;
    total: number;
    status: 'parsing' | 'uploading' | 'completed' | 'error';
    message: string;
    results?: {
      successful: number;
      failed: number;
      duplicates: number;
    };
  }>({
    isImporting: false,
    current: 0,
    total: 0,
    status: 'parsing',
    message: '',
  });

  // Inline Edit State
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editForm, setEditForm] = useState<ContactPayload>({ name: '', phone: '', address: '', isFavorite: false });

  // Quick Add State
  const [showQuickAdd, setShowQuickAdd] = useState(false);
  const [quickAddData, setQuickAddData] = useState({ name: '', phone: '' });

  // Delete Confirmation State
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [contactToDelete, setContactToDelete] = useState<number | null>(null);

  // Emergency Contact Modal State
  const [isEmergencyModalOpen, setIsEmergencyModalOpen] = useState(false);
  const [emergencyContactTarget, setEmergencyContactTarget] = useState<Contact | null>(null);
  const [emergencyError, setEmergencyError] = useState('');
  const [isEditingEmergency, setIsEditingEmergency] = useState(false);
  const [editingEmergencyId, setEditingEmergencyId] = useState<number | null>(null);
  const [emergencyForm, setEmergencyForm] = useState({
    name: '',
    phone: '',
    email: '',
    relationship: 'spouse'
  });

  const relationshipOptions = ['spouse', 'parent', 'sibling', 'friend', 'doctor', 'lawyer', 'other'] as const;
  const phonePattern = /^[0-9+().\-\s]{7,20}$/;
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  // SIP / VoIP State
  const [sipAccounts, setSipAccounts] = useState<SipAccount[]>([]);
  const [sipLoading, setSipLoading] = useState(false);
  const [sipError, setSipError] = useState('');
  const [sipPasswords, setSipPasswords] = useState<Record<number, string>>({});
  const [isSipModalOpen, setIsSipModalOpen] = useState(false);
  const [editingSipId, setEditingSipId] = useState<number | null>(null);
  const [sipForm, setSipForm] = useState<SipAccountPayload>({
    label: '',
    server_type: 'generic',
    server_host: '',
    server_port: 5060,
    username: '',
    password: '',
    extension: '',
    transport: 'wss',
    ws_path: '/ws'
  });
  const [activeSipAccountId, setActiveSipAccountId] = useState<number | null>(null);

  // Call State
  const [isCallModalOpen, setIsCallModalOpen] = useState(false);
  const [callTarget, setCallTarget] = useState<Contact | null>(null);
  const [callStatus, setCallStatus] = useState<'idle' | 'connecting' | 'ringing' | 'in_call' | 'ended' | 'failed'>('idle');
  const [callError, setCallError] = useState('');
  const [callLogs, setCallLogs] = useState<CallLog[]>([]);
  const uaRef = useRef<any>(null);
  const sessionRef = useRef<any>(null);
  const callStartRef = useRef<number | null>(null);
  const callAnsweredRef = useRef<number | null>(null);

  // Pagination State
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  const fetchContacts = async (search?: string) => {
    setLoading(true);
    try {
      const data = await contactService.getContacts(search, currentPage, itemsPerPage);
      setContacts(data);
    } catch (err) {
      console.error(err);
      setError('Failed to fetch contacts');
    } finally {
      setLoading(false);
    }
  };

  const fetchSipAccounts = async () => {
    setSipLoading(true);
    setSipError('');
    try {
      const data = await sipService.getSipAccounts();
      setSipAccounts(data);
      if (data.length && activeSipAccountId === null) {
        setActiveSipAccountId(data[0].id);
      }
    } catch (err: any) {
      setSipError(err.message || 'Failed to load SIP accounts');
    } finally {
      setSipLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchContacts(searchTerm);
      setCurrentPage(1); // Reset to first page when searching
    }, 300);
    return () => clearTimeout(timer);
  }, [searchTerm]);

  useEffect(() => {
    fetchContacts(searchTerm);
  }, [currentPage]);

  useEffect(() => {
    fetchSipAccounts();
  }, []);

  // Modal Save (New Contact or Fallback)
  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canModify) {
      setError('View-only access: you cannot add or edit contacts.');
      return;
    }
    try {
      if (currentContact.id) {
        await contactService.updateContact(currentContact.id, currentContact as ContactPayload);
      } else {
        await contactService.createContact(currentContact as ContactPayload);
      }
      setIsModalOpen(false);
      fetchContacts(searchTerm);
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleQuickSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickAddData.name || !quickAddData.phone) return;
    if (!canModify) return;
    
    try {
        await contactService.createContact({ ...quickAddData, isFavorite: false });
        setQuickAddData({ name: '', phone: '' });
        setShowQuickAdd(false);
        fetchContacts(searchTerm);
    } catch (err: any) {
        alert(err.message || 'Failed to create contact');
    }
  };

  // Inline Editing Handlers
  const startEditing = (contact: Contact) => {
    if (!canModify) return;
    setEditingId(contact.id);
    setEditForm({
      name: contact.name,
      phone: contact.phone,
      address: contact.address || '',
      isFavorite: contact.isFavorite || false
    });
  };

  const cancelEditing = () => {
    setEditingId(null);
    setEditForm({ name: '', phone: '', address: '', isFavorite: false });
  };

  const saveEditing = async (id: number) => {
    if (!canModify) return;
    try {
      await contactService.updateContact(id, editForm);
      setEditingId(null);
      fetchContacts(searchTerm);
    } catch (err: any) {
      alert(err.message || 'Failed to update contact');
    }
  };

  const handleToggleFavorite = async (contact: Contact) => {
    if (!canModify) return;
    const updatedContact = { ...contact, isFavorite: !contact.isFavorite };
    // Optimistic update
    setContacts(prev => prev.map(c => c.id === contact.id ? updatedContact : c));

    try {
        await contactService.updateContact(contact.id, updatedContact as ContactPayload);
    } catch (err) {
        // Revert on failure
        setContacts(prev => prev.map(c => c.id === contact.id ? contact : c));
        console.error("Failed to update favorite status");
    }
  };

  const initiateDelete = (id: number) => {
    if (!canDelete) return;
    setContactToDelete(id);
    setIsDeleteModalOpen(true);
  };

  const confirmDelete = async () => {
    if (contactToDelete === null) return;
    if (!canDelete) return;
    
    try {
      await contactService.deleteContact(contactToDelete);
      fetchContacts(searchTerm);
    } catch (err: any) {
      alert(err.message);
    } finally {
      setIsDeleteModalOpen(false);
      setContactToDelete(null);
    }
  };

  const openEmergencyModal = (contact: Contact) => {
    if (!canModify) return;
    setEmergencyContactTarget(contact);
    setEmergencyError('');
    setIsEditingEmergency(false);
    setEditingEmergencyId(null);
    setEmergencyForm({ name: '', phone: '', email: '', relationship: 'spouse' });
    setIsEmergencyModalOpen(true);
  };

  const openEmergencyEdit = (contact: Contact, emergencyId: number) => {
    if (!canModify) return;
    const existing = contact.emergencyContacts?.find(ec => ec.id === emergencyId);
    if (!existing) return;
    setEmergencyContactTarget(contact);
    setEmergencyError('');
    setIsEditingEmergency(true);
    setEditingEmergencyId(emergencyId);
    setEmergencyForm({
      name: existing.name,
      phone: existing.phone,
      email: existing.email,
      relationship: existing.relationship
    });
    setIsEmergencyModalOpen(true);
  };

  const handleEmergencyDelete = async (contact: Contact, emergencyId: number) => {
    if (!canModify) return;
    const ok = window.confirm('Delete this emergency contact?');
    if (!ok) return;
    try {
      await contactService.deleteEmergencyContact(contact.id, emergencyId);
      fetchContacts(searchTerm);
    } catch (err: any) {
      alert(err.message || 'Failed to delete emergency contact');
    }
  };

  const handleEmergencySave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canModify || !emergencyContactTarget) return;

    if (!phonePattern.test(emergencyForm.phone)) {
      setEmergencyError('Please enter a valid phone number.');
      return;
    }
    if (!emailPattern.test(emergencyForm.email)) {
      setEmergencyError('Please enter a valid email address.');
      return;
    }

    try {
      if (isEditingEmergency && editingEmergencyId !== null) {
        await contactService.updateEmergencyContact(
          emergencyContactTarget.id,
          editingEmergencyId,
          emergencyForm
        );
      } else {
        await contactService.addEmergencyContact(emergencyContactTarget.id, emergencyForm);
      }
      setIsEmergencyModalOpen(false);
      setEmergencyContactTarget(null);
      setIsEditingEmergency(false);
      setEditingEmergencyId(null);
      fetchContacts(searchTerm);
    } catch (err: any) {
      setEmergencyError(err.message || 'Failed to add emergency contact');
    }
  };

  const openSipModal = () => {
    if (!canModify) return;
    setEditingSipId(null);
    setSipForm({
      label: '',
      server_type: 'generic',
      server_host: '',
      server_port: 5060,
      username: '',
      password: '',
      extension: '',
      transport: 'wss',
      ws_path: '/ws'
    });
    setSipError('');
    setIsSipModalOpen(true);
  };

  const editSipAccount = (account: SipAccount) => {
    if (!canModify) return;
    setEditingSipId(account.id);
    setSipForm({
      label: account.label || '',
      server_type: account.server_type,
      server_host: account.server_host,
      server_port: account.server_port,
      username: account.username,
      password: '',
      extension: account.extension || '',
      transport: account.transport,
      ws_path: account.ws_path || '/ws'
    });
    setSipError('');
    setIsSipModalOpen(true);
  };

  const saveSipAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canModify) return;
    try {
      if (editingSipId) {
        await sipService.updateSipAccount(editingSipId, sipForm);
        if (sipForm.password) {
          setSipPasswords(prev => ({ ...prev, [editingSipId]: sipForm.password || '' }));
        }
      } else {
        if (!sipForm.password) {
          setSipError('Password is required for new SIP accounts.');
          return;
        }
        const created = await sipService.createSipAccount(sipForm);
        setSipPasswords(prev => ({ ...prev, [created.id]: sipForm.password || '' }));
      }
      setIsSipModalOpen(false);
      fetchSipAccounts();
    } catch (err: any) {
      setSipError(err.message || 'Failed to save SIP account');
    }
  };

  const removeSipAccount = async (id: number) => {
    if (!canModify) return;
    const ok = window.confirm('Delete this SIP account?');
    if (!ok) return;
    try {
      await sipService.deleteSipAccount(id);
      fetchSipAccounts();
    } catch (err: any) {
      setSipError(err.message || 'Failed to delete SIP account');
    }
  };

  const buildWsUrl = (account: SipAccount) => {
    const path = account.ws_path && account.ws_path.startsWith('/') ? account.ws_path : `/${account.ws_path || 'ws'}`;
    const protocol = account.transport === 'wss' ? 'wss' : 'ws';
    return `${protocol}://${account.server_host}:${account.server_port}${path}`;
  };

  const openCallModal = async (contact: Contact) => {
    setCallTarget(contact);
    setCallStatus('idle');
    setCallError('');
    setIsCallModalOpen(true);
    try {
      const logs = await callLogService.getCallLogsForContact(contact.id);
      setCallLogs(logs);
    } catch (err: any) {
      setCallLogs([]);
    }
  };

  const endSipSession = () => {
    try {
      sessionRef.current?.terminate?.();
    } catch (err) {
      // ignore
    }
    try {
      uaRef.current?.stop?.();
    } catch (err) {
      // ignore
    }
    sessionRef.current = null;
    uaRef.current = null;
  };

  const logCall = async (status: CallLog['status']) => {
    if (!callTarget) return;
    const account = sipAccounts.find(a => a.id === activeSipAccountId) || null;
    const startedAt = callStartRef.current ? new Date(callStartRef.current).toISOString() : new Date().toISOString();
    const endedAt = new Date().toISOString();
    const durationSeconds = callAnsweredRef.current ? Math.max(0, Math.floor((Date.now() - callAnsweredRef.current) / 1000)) : 0;

    try {
      await callLogService.createCallLog({
        contact_id: callTarget.id,
        sip_account_id: account?.id || null,
        phone_number: callTarget.phone,
        direction: 'outbound',
        status,
        duration_seconds: durationSeconds,
        started_at: startedAt,
        ended_at: endedAt
      });
      const logs = await callLogService.getCallLogsForContact(callTarget.id);
      setCallLogs(logs);
    } catch (err) {
      // swallow logging errors
    }
  };

  const startCall = async () => {
    if (!callTarget) return;
    const account = sipAccounts.find(a => a.id === activeSipAccountId);
    if (!account) {
      setCallError('No SIP account configured. Add one in SIP Settings.');
      return;
    }
    const accountPassword = sipPasswords[account.id];
    if (!accountPassword) {
      setCallError('SIP password not set for this account. Edit the SIP account to add it.');
      return;
    }
    if (account.transport !== 'wss') {
      setCallError('Browser softphone requires WSS transport. Update your SIP account.');
      return;
    }

    setCallStatus('connecting');
    setCallError('');
    callStartRef.current = Date.now();
    callAnsweredRef.current = null;

    try {
      const socket = new JsSIP.WebSocketInterface(buildWsUrl(account));
      const ua = new JsSIP.UA({
        sockets: [socket],
        uri: `sip:${account.username}@${account.server_host}`,
        password: accountPassword,
        register: true
      });

      uaRef.current = ua;
      ua.start();

      const session = ua.call(`sip:${callTarget.phone}@${account.server_host}`, {
        mediaConstraints: { audio: true, video: false }
      });

      sessionRef.current = session;

      session.on('progress', () => setCallStatus('ringing'));
      session.on('confirmed', () => {
        callAnsweredRef.current = Date.now();
        setCallStatus('in_call');
      });
      session.on('ended', async () => {
        setCallStatus('ended');
        await logCall(callAnsweredRef.current ? 'completed' : 'canceled');
        endSipSession();
      });
      session.on('failed', async () => {
        setCallStatus('failed');
        await logCall('failed');
        endSipSession();
      });
    } catch (err: any) {
      setCallStatus('failed');
      setCallError(err.message || 'Failed to start call');
      endSipSession();
    }
  };

  const hangupCall = async () => {
    if (!sessionRef.current) return;
    sessionRef.current.terminate();
    setCallStatus('ended');
    await logCall(callAnsweredRef.current ? 'completed' : 'canceled');
    endSipSession();
  };

  const handleExport = async () => {
    const token = localStorage.getItem('token');
    const response = await fetch(contactService.exportContactsUrl, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (response.ok) {
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `contacts_${new Date().toISOString().split('T')[0]}.csv`;
      a.click();
    }
  };

  const handleFileImport = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const fileExtension = file.name.split('.').pop()?.toLowerCase();
    if (!['csv', 'xlsx', 'xls'].includes(fileExtension)) {
      alert('Please upload a CSV or Excel file (.csv, .xlsx, .xls)');
      return;
    }

    if (!canModify) {
      setError('View-only access: you cannot import contacts.');
      return;
    }

    try {
      // Start import process
      setImportProgress({
        isImporting: true,
        current: 0,
        total: 0,
        status: 'parsing',
        message: 'Reading file...',
      });

      const text = await file.text();
      const contacts = parseContactsFile(text, fileExtension);
      
      setImportProgress(prev => ({
        ...prev,
        total: contacts.length,
        status: 'uploading',
        message: `Importing ${contacts.length} contacts...`,
      }));

      // Import contacts with progress tracking
      let successful = 0;
      let failed = 0;
      let duplicates = 0;

      for (let i = 0; i < contacts.length; i++) {
        try {
          await contactService.createContact(contacts[i]);
          successful++;
        } catch (err) {
          console.error(`Failed to import contact ${i + 1}:`, err);
          failed++;
          
          // Check if it's a duplicate error
          if (err instanceof Error && err.message.includes('duplicate')) {
            duplicates++;
          }
        }

        // Update progress
        setImportProgress(prev => ({
          ...prev,
          current: i + 1,
          message: `Importing ${i + 1} of ${contacts.length} contacts...`,
        }));

        // Small delay to show progress
        await new Promise(resolve => setTimeout(resolve, 100));
      }

      // Complete import
      setImportProgress({
        isImporting: false,
        current: contacts.length,
        total: contacts.length,
        status: 'completed',
        message: 'Import completed!',
        results: { successful, failed, duplicates }
      });

      // Refresh contacts and close modal after delay
      setTimeout(() => {
        setIsImportModalOpen(false);
        fetchContacts(searchTerm);
        setImportProgress({
          isImporting: false,
          current: 0,
          total: 0,
          status: 'parsing',
          message: '',
        });
      }, 2000);

    } catch (err) {
      console.error('Import error:', err);
      setImportProgress({
        isImporting: false,
        current: 0,
        total: 0,
        status: 'error',
        message: 'Failed to import contacts. Please check your file format.',
      });
    }
  };

  const parseContactsFile = (text: string, fileExtension: string): ContactPayload[] => {
    const lines = text.split('\n').filter(line => line.trim());
    
    if (fileExtension === 'csv') {
      return parseCSV(lines);
    } else {
      // For Excel files, you'd need a library like xlsx
      // For now, let's try to parse as CSV (Excel files can be saved as CSV)
      return parseCSV(lines);
    }
  };

  const parseCSV = (lines: string[]): ContactPayload[] => {
    const contacts: ContactPayload[] = [];
    
    // Skip header if present
    const startIndex = lines[0]?.toLowerCase().includes('name') ? 1 : 0;
    
    for (let i = startIndex; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      
      // Simple CSV parsing - assumes format: name,phone,address
      const parts = line.split(',').map(part => part.trim().replace(/^"|"$/g, ''));
      
      if (parts.length >= 2) {
        contacts.push({
          name: parts[0] || '',
          phone: parts[1] || '',
          address: parts[2] || '',
          isFavorite: false
        });
      }
    }
    
    return contacts;
  };

  const openAdd = () => {
    if (!canModify) return;
    setCurrentContact({ name: '', phone: '', address: '', isFavorite: false });
    setIsModalOpen(true);
  };

  // Filter and Sort: Favorites first, then alphabetical
  const displayedContacts = contacts
    .filter(c => !showFavorites || c.isFavorite)
    .sort((a, b) => {
        // Favorites always on top
        if (a.isFavorite && !b.isFavorite) return -1;
        if (!a.isFavorite && b.isFavorite) return 1;
        // Then by name
        return a.name.localeCompare(b.name);
    });

  // Pagination logic
  const totalPages = Math.ceil(displayedContacts.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedContacts = displayedContacts.slice(startIndex, endIndex);

  // Reset to page 1 if current page is out of bounds
  useEffect(() => {
    if (currentPage > totalPages && totalPages > 0) {
      setCurrentPage(1);
    }
  }, [currentPage, totalPages]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Phone Directory</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Manage your professional and personal network.</p>
        </div>
        <div className="flex flex-wrap gap-2 w-full sm:w-auto">
           <button
             onClick={() => setShowFavorites(!showFavorites)}
             className={`flex-1 sm:flex-none inline-flex items-center justify-center px-4 py-2 border shadow-sm text-sm font-medium rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-500 transition-colors ${
                 showFavorites 
                    ? 'border-yellow-400 bg-yellow-50 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400 dark:border-yellow-600' 
                    : 'border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700'
             }`}
           >
             <Star className={`w-4 h-4 mr-2 ${showFavorites ? 'fill-yellow-400 text-yellow-400' : ''}`} />
             {showFavorites ? 'Favorites Only' : 'Favorites'}
           </button>
           
           {canModify && (
             <button
              onClick={() => { setShowQuickAdd(!showQuickAdd); if(!showQuickAdd) setTimeout(() => document.getElementById('quick-name')?.focus(), 50); }}
              className={`flex-1 sm:flex-none inline-flex items-center justify-center px-4 py-2 border shadow-sm text-sm font-medium rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors ${
                  showQuickAdd
                  ? 'bg-indigo-50 text-indigo-700 border-indigo-200 dark:bg-indigo-900/30 dark:text-indigo-300 dark:border-indigo-700'
                  : 'border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700'
              }`}
             >
              <Zap className={`w-4 h-4 mr-2 ${showQuickAdd ? 'text-indigo-600 dark:text-indigo-400 fill-current' : ''}`} />
             Quick Add
             </button>
           )}

           {canModify && (
             <button
              onClick={openSipModal}
              className="flex-1 sm:flex-none inline-flex items-center justify-center px-4 py-2 border border-gray-300 dark:border-gray-600 shadow-sm text-sm font-medium rounded-md text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
             >
              <Settings className="w-4 h-4 mr-2" />
              SIP Settings
             </button>
           )}

           <button
            onClick={handleExport}
            className="flex-1 sm:flex-none inline-flex items-center justify-center px-4 py-2 border border-gray-300 dark:border-gray-600 shadow-sm text-sm font-medium rounded-md text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
          >
            <Download className="w-4 h-4 mr-2" />
            Export
          </button>
          {canModify && (
            <button
              onClick={() => setIsImportModalOpen(true)}
              className="flex-1 sm:flex-none inline-flex items-center justify-center px-4 py-2 border border-gray-300 dark:border-gray-600 shadow-sm text-sm font-medium rounded-md text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
            >
              <Upload className="w-4 h-4 mr-2" />
              Import
            </button>
          )}
          {canModify && (
            <button
              onClick={openAdd}
              className="flex-1 sm:flex-none inline-flex items-center justify-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
            >
              <Plus className="w-4 h-4 mr-2" />
              Add Contact
            </button>
          )}
        </div>
      </div>

      <div className="relative">
        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <Search className="h-5 w-5 text-gray-400" />
        </div>
        <input
          type="text"
          className="block w-full pl-10 pr-3 py-3 border border-gray-300 dark:border-gray-600 rounded-lg leading-5 bg-white dark:bg-gray-800 placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:placeholder-gray-400 focus:ring-1 focus:ring-primary-500 focus:border-primary-500 sm:text-sm shadow-sm text-gray-900 dark:text-white"
          placeholder="Search contacts (e.g. 'Sarah', '555-0199', 'CA Tech')..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
      </div>

      {loading ? (
        <div className="flex justify-center py-12">
          <Loader2 className="w-8 h-8 animate-spin text-primary-600" />
        </div>
      ) : displayedContacts.length === 0 && !showQuickAdd ? (
        <div className="text-center py-12 bg-white dark:bg-gray-800 rounded-lg border border-dashed border-gray-300 dark:border-gray-700">
           <User className="mx-auto h-12 w-12 text-gray-400" />
           <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No contacts found</h3>
           <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
               {showFavorites && searchTerm 
                ? "No favorite contacts match your search." 
                : showFavorites 
                ? "You haven't marked any contacts as favorites yet."
                : canModify ? "Get started by creating a new contact." : "No contacts to display."}
           </p>
           {!showFavorites && canModify && (
               <div className="mt-6">
                 <button
                   onClick={openAdd}
                   className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700"
                 >
                   <Plus className="w-4 h-4 mr-2" />
                   New Contact
                 </button>
               </div>
           )}
        </div>
      ) : (
        <div className="bg-white dark:bg-gray-800 shadow overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700">
          <ul className="divide-y divide-gray-200 dark:divide-gray-700">
            {/* Inline Quick Add Form */}
            {showQuickAdd && (
                <li className="bg-indigo-50 dark:bg-indigo-900/10 p-4 border-b border-indigo-100 dark:border-indigo-800/50 animate-fadeIn">
                    <form onSubmit={handleQuickSave} className="flex flex-col sm:flex-row gap-3 items-center">
                        <div className="flex-1 w-full">
                            <input 
                                id="quick-name"
                                type="text" 
                                placeholder="Name"
                                required
                                className="block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                                value={quickAddData.name}
                                onChange={e => setQuickAddData({...quickAddData, name: e.target.value})}
                            />
                        </div>
                        <div className="flex-1 w-full">
                            <input 
                                type="tel" 
                                placeholder="Phone"
                                required
                                className="block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                                value={quickAddData.phone}
                                onChange={e => setQuickAddData({...quickAddData, phone: e.target.value})}
                            />
                        </div>
                        <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
                            <button 
                                type="button" 
                                onClick={() => setShowQuickAdd(false)}
                                className="inline-flex items-center p-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none"
                                title="Cancel"
                            >
                                <X className="h-4 w-4" />
                            </button>
                            <button 
                                type="submit"
                                className="inline-flex items-center p-2 border border-transparent rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none"
                                title="Save Contact"
                            >
                                <Save className="h-4 w-4 mr-1" />
                                <span className="text-sm font-medium">Save</span>
                            </button>
                        </div>
                    </form>
                </li>
            )}

            {paginatedContacts.map((contact) => (
              <li key={contact.id} className="hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors duration-150">
                {editingId === contact.id ? (
                  // Inline Edit View
                  <div className="px-4 py-4 sm:px-6">
                    <div className="flex items-start gap-3">
                       <div className="bg-primary-100 dark:bg-primary-900/50 p-2 rounded-full shrink-0 mt-1">
                           <User className="h-5 w-5 text-primary-600 dark:text-primary-400" />
                       </div>
                       <div className="flex-1 space-y-3">
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                             <div>
                                <input
                                    type="text"
                                    className="block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                                    placeholder="Name"
                                    value={editForm.name}
                                    onChange={(e) => setEditForm({...editForm, name: e.target.value})}
                                    autoFocus
                                />
                             </div>
                             <div>
                                <input
                                    type="text"
                                    className="block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                                    placeholder="Phone"
                                    value={editForm.phone}
                                    onChange={(e) => setEditForm({...editForm, phone: e.target.value})}
                                />
                             </div>
                          </div>
                          <div>
                             <input
                                type="text"
                                className="block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                                placeholder="Address (optional)"
                                value={editForm.address || ''}
                                onChange={(e) => setEditForm({...editForm, address: e.target.value})}
                             />
                          </div>
                       </div>
                       <div className="flex flex-col gap-2 ml-2">
                          <button onClick={() => saveEditing(contact.id)} className="p-2 text-green-600 hover:bg-green-50 dark:hover:bg-green-900/20 rounded-full transition-colors" title="Save Changes">
                            <Check className="w-5 h-5" />
                          </button>
                          <button onClick={cancelEditing} className="p-2 text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-full transition-colors" title="Cancel Edit">
                            <X className="w-5 h-5" />
                          </button>
                       </div>
                    </div>
                  </div>
                ) : (
                  // Standard View
                  <div className="px-4 py-4 sm:px-6">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center min-w-0 gap-3">
                            {canModify ? (
                              <button 
                                  onClick={(e) => { e.stopPropagation(); handleToggleFavorite(contact); }}
                                  className="focus:outline-none transition-transform active:scale-95"
                                  title={contact.isFavorite ? "Remove from favorites" : "Add to favorites"}
                              >
                                  <Star 
                                      className={`w-5 h-5 ${
                                          contact.isFavorite 
                                          ? 'fill-yellow-400 text-yellow-400' 
                                          : 'text-gray-300 hover:text-yellow-400'
                                      }`} 
                                  />
                              </button>
                            ) : (
                              <span title={contact.isFavorite ? "Favorite" : "Not favorite"}>
                                <Star 
                                  className={`w-5 h-5 ${
                                      contact.isFavorite 
                                      ? 'fill-yellow-400 text-yellow-400' 
                                      : 'text-gray-300'
                                  }`} 
                                />
                              </span>
                            )}
                            <div className="bg-primary-100 dark:bg-primary-900/50 p-2 rounded-full">
                            <User className="h-5 w-5 text-primary-600 dark:text-primary-400" />
                            </div>
                            <div className="truncate">
                                <p className="text-sm font-medium text-primary-600 dark:text-primary-400 truncate flex items-center gap-2">
                                    {contact.name}
                                </p>
                                <p className="flex items-center text-sm text-gray-500 dark:text-gray-400 mt-1">
                                    <Phone className="flex-shrink-0 mr-1.5 h-3.5 w-3.5 text-gray-400" />
                                    {contact.phone}
                                </p>
                            </div>
                        </div>
                        <div className="flex gap-2">
                          {canModify && (
                            <button
                              onClick={() => openCallModal(contact)}
                              className="p-2 text-gray-400 hover:text-green-600 hover:bg-green-50 dark:hover:bg-green-900/20 rounded-full transition-colors"
                              title="Call via SIP"
                            >
                              <Phone className="w-4 h-4" />
                            </button>
                          )}
                          {canModify && (
                            <button onClick={() => startEditing(contact)} className="p-2 text-gray-400 hover:text-primary-600 hover:bg-primary-50 dark:hover:bg-gray-700 rounded-full transition-colors">
                                <Edit2 className="w-4 h-4" />
                            </button>
                          )}
                          {canDelete && (
                            <button onClick={() => initiateDelete(contact.id)} className="p-2 text-gray-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-full transition-colors">
                                <Trash2 className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                    </div>
                    {contact.address && (
                        <div className="mt-2 sm:flex sm:justify-between ml-10 pl-1">
                        <div className="sm:flex">
                            <p className="flex items-center text-sm text-gray-500 dark:text-gray-400">
                            <MapPin className="flex-shrink-0 mr-1.5 h-3.5 w-3.5 text-gray-400" />
                            {contact.address}
                            </p>
                        </div>
                        </div>
                    )}

                    {(contact.emergencyContacts?.length || canModify) && (
                      <div className="mt-4 ml-10 pl-1 border-t border-dashed border-gray-200 dark:border-gray-700 pt-3">
                        <div className="flex items-center justify-between">
                          <p className="text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">
                            Emergency Contacts
                          </p>
                          {canModify && (
                            <button
                              onClick={() => openEmergencyModal(contact)}
                              className="text-xs font-semibold text-primary-600 dark:text-primary-400 hover:text-primary-700"
                            >
                              Add Emergency
                            </button>
                          )}
                        </div>
                        {contact.emergencyContacts && contact.emergencyContacts.length > 0 ? (
                          <div className="mt-3 grid gap-2 sm:grid-cols-2">
                            {contact.emergencyContacts.map((ec) => (
                              <div key={ec.id} className="rounded-lg border border-amber-200/60 dark:border-amber-700/60 bg-amber-50/60 dark:bg-amber-900/20 p-3">
                                <div className="flex items-center justify-between gap-2">
                                  <div>
                                    <p className="text-sm font-semibold text-gray-900 dark:text-white">{ec.name}</p>
                                    <span className="text-[11px] uppercase tracking-wide text-amber-700 dark:text-amber-200">
                                      {ec.relationship}
                                    </span>
                                  </div>
                                  {canModify && (
                                    <div className="flex items-center gap-2">
                                      <button
                                        onClick={() => openCallModal({ ...contact, name: `${ec.name} (Emergency)`, phone: ec.phone })}
                                        className="text-xs text-gray-500 hover:text-green-600"
                                        title="Call emergency contact via SIP"
                                      >
                                        Call
                                      </button>
                                      <button
                                        onClick={() => openEmergencyEdit(contact, ec.id)}
                                        className="text-xs text-gray-500 hover:text-primary-600"
                                      >
                                        Edit
                                      </button>
                                      <button
                                        onClick={() => handleEmergencyDelete(contact, ec.id)}
                                        className="text-xs text-red-500 hover:text-red-600"
                                      >
                                        Delete
                                      </button>
                                    </div>
                                  )}
                                </div>
                                <p className="text-xs text-gray-600 dark:text-gray-300 mt-1">{ec.phone}</p>
                                <p className="text-xs text-gray-500 dark:text-gray-400">{ec.email}</p>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">No emergency contacts listed.</p>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </li>
            ))}
          </ul>
          
          {/* Pagination Controls - Integrated within the contact list */}
          {totalPages > 1 && (
            <div className="border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/50 px-4 py-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center text-sm text-gray-700 dark:text-gray-300">
                  <span>
                    Showing {startIndex + 1} to {Math.min(endIndex, displayedContacts.length)} of {displayedContacts.length} contacts
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                    disabled={currentPage === 1}
                    className="relative inline-flex items-center px-3 py-2 text-sm font-medium text-gray-500 dark:text-gray-400 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Previous
                  </button>
                  
                  <div className="flex items-center gap-1">
                    {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => {
                      let pageNum;
                      if (totalPages <= 5) {
                        pageNum = i + 1;
                      } else if (currentPage <= 3) {
                        pageNum = i + 1;
                      } else if (currentPage >= totalPages - 2) {
                        pageNum = totalPages - 4 + i;
                      } else {
                        pageNum = currentPage - 2 + i;
                      }
                      
                      return (
                        <button
                          key={pageNum}
                          onClick={() => setCurrentPage(pageNum)}
                          className={`relative inline-flex items-center px-3 py-2 text-sm font-medium rounded-md ${
                            currentPage === pageNum
                              ? 'bg-primary-600 text-white'
                              : 'text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700'
                          }`}
                        >
                          {pageNum}
                        </button>
                      );
                    })}
                  </div>
                  
                  <button
                    onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                    disabled={currentPage === totalPages}
                    className="relative inline-flex items-center px-3 py-2 text-sm font-medium text-gray-500 dark:text-gray-400 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Next
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Add Modal (Edit logic moved to inline) */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Add New Contact"
      >
        <form onSubmit={handleSave} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Name</label>
            <input
              type="text"
              required
              className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              value={currentContact.name || ''}
              onChange={(e) => setCurrentContact({ ...currentContact, name: e.target.value })}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Phone</label>
            <input
              type="tel"
              required
              className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              value={currentContact.phone || ''}
              onChange={(e) => setCurrentContact({ ...currentContact, phone: e.target.value })}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Address</label>
            <textarea
              className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              rows={3}
              value={currentContact.address || ''}
              onChange={(e) => setCurrentContact({ ...currentContact, address: e.target.value })}
            />
          </div>
          
          <div className="flex items-center gap-2">
              <input 
                id="modalIsFavorite"
                type="checkbox"
                className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                checked={currentContact.isFavorite || false}
                onChange={(e) => setCurrentContact({ ...currentContact, isFavorite: e.target.checked })}
              />
              <label htmlFor="modalIsFavorite" className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  Mark as Favorite
              </label>
          </div>

          {error && <p className="text-red-500 text-sm">{error}</p>}
          <div className="flex justify-end gap-3 mt-5">
            <button
              type="button"
              onClick={() => setIsModalOpen(false)}
              className="inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 shadow-sm hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="inline-flex justify-center rounded-md border border-transparent bg-primary-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2"
            >
              Save
            </button>
          </div>
        </form>
      </Modal>

      {/* SIP Settings Modal */}
      <Modal
        isOpen={isSipModalOpen}
        onClose={() => {
          setIsSipModalOpen(false);
          setSipError('');
        }}
        title="SIP Settings"
      >
        <div className="space-y-6">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Accounts</h3>
              {sipLoading && <Loader2 className="w-4 h-4 animate-spin text-gray-400" />}
            </div>
            {sipAccounts.length === 0 ? (
              <p className="text-sm text-gray-500 dark:text-gray-400">No SIP accounts configured.</p>
            ) : (
              <div className="space-y-2">
                {sipAccounts.map(account => (
                  <div key={account.id} className="flex items-center justify-between gap-3 rounded-md border border-gray-200 dark:border-gray-700 p-3">
                    <div>
                      <p className="text-sm font-medium text-gray-900 dark:text-white">
                        {account.label || `${account.server_type.toUpperCase()} @ ${account.server_host}`}
                      </p>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        {account.username} · {account.server_host}:{account.server_port} · {account.transport.toUpperCase()}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setActiveSipAccountId(account.id)}
                        className={`text-xs px-2 py-1 rounded-full border ${
                          activeSipAccountId === account.id
                            ? 'border-green-500 text-green-600'
                            : 'border-gray-300 text-gray-500'
                        }`}
                      >
                        {activeSipAccountId === account.id ? 'Active' : 'Use'}
                      </button>
                      <button onClick={() => editSipAccount(account)} className="text-xs text-primary-600 hover:text-primary-700">
                        Edit
                      </button>
                      <button onClick={() => removeSipAccount(account.id)} className="text-xs text-red-500 hover:text-red-600">
                        Delete
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="border-t border-gray-200 dark:border-gray-700 pt-5">
            <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
              {editingSipId ? 'Edit SIP Account' : 'Add SIP Account'}
            </h3>
            <form onSubmit={saveSipAccount} className="space-y-3">
              <div className="grid sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-600 dark:text-gray-300">Label</label>
                  <input
                    type="text"
                    className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    value={sipForm.label || ''}
                    onChange={(e) => setSipForm({ ...sipForm, label: e.target.value })}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 dark:text-gray-300">Server Type</label>
                  <select
                    className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    value={sipForm.server_type}
                    onChange={(e) => setSipForm({ ...sipForm, server_type: e.target.value as SipAccountPayload['server_type'] })}
                  >
                    <option value="grandstream">Grandstream</option>
                    <option value="asterisk">Asterisk</option>
                    <option value="freepbx">FreePBX</option>
                    <option value="generic">Generic SIP</option>
                  </select>
                </div>
              </div>
              <div className="grid sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-600 dark:text-gray-300">Server Host</label>
                  <input
                    type="text"
                    required
                    className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    value={sipForm.server_host}
                    onChange={(e) => setSipForm({ ...sipForm, server_host: e.target.value })}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 dark:text-gray-300">Server Port</label>
                  <input
                    type="number"
                    className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    value={sipForm.server_port || 5060}
                    onChange={(e) => setSipForm({ ...sipForm, server_port: Number(e.target.value) })}
                  />
                </div>
              </div>
              <div className="grid sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-600 dark:text-gray-300">Transport</label>
                  <select
                    className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    value={sipForm.transport || 'wss'}
                    onChange={(e) => setSipForm({ ...sipForm, transport: e.target.value as SipAccountPayload['transport'] })}
                  >
                    <option value="wss">WSS (WebRTC)</option>
                    <option value="tls">TLS</option>
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 dark:text-gray-300">WS Path</label>
                  <input
                    type="text"
                    className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    value={sipForm.ws_path || '/ws'}
                    onChange={(e) => setSipForm({ ...sipForm, ws_path: e.target.value })}
                  />
                </div>
              </div>
              <div className="grid sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-600 dark:text-gray-300">Username</label>
                  <input
                    type="text"
                    required
                    className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    value={sipForm.username}
                    onChange={(e) => setSipForm({ ...sipForm, username: e.target.value })}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 dark:text-gray-300">
                    Password {editingSipId ? '(leave blank to keep)' : ''}
                  </label>
                  <input
                    type="password"
                    className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    value={sipForm.password || ''}
                    onChange={(e) => setSipForm({ ...sipForm, password: e.target.value })}
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 dark:text-gray-300">Extension</label>
                <input
                  type="text"
                  className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  value={sipForm.extension || ''}
                  onChange={(e) => setSipForm({ ...sipForm, extension: e.target.value })}
                />
              </div>
              <p className="text-xs text-amber-600 dark:text-amber-300">
                Browser calling requires WSS transport and WebRTC enabled on your SIP server.
              </p>
              {sipError && <p className="text-sm text-red-500">{sipError}</p>}
              <div className="flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setIsSipModalOpen(false)}
                  className="inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 shadow-sm hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="inline-flex justify-center rounded-md border border-transparent bg-primary-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2"
                >
                  {editingSipId ? 'Update' : 'Save'}
                </button>
              </div>
            </form>
          </div>
        </div>
      </Modal>

      {/* Call Modal */}
      <Modal
        isOpen={isCallModalOpen}
        onClose={() => {
          setIsCallModalOpen(false);
          setCallTarget(null);
          setCallStatus('idle');
          setCallError('');
          endSipSession();
        }}
        title={callTarget ? `Call ${callTarget.name}` : 'Call'}
      >
        <div className="space-y-4">
          <div className="flex flex-col gap-2">
            <label className="text-xs font-medium text-gray-600 dark:text-gray-300">SIP Account</label>
            <select
              className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              value={activeSipAccountId || ''}
              onChange={(e) => setActiveSipAccountId(Number(e.target.value))}
              disabled={sipAccounts.length === 0}
            >
              {sipAccounts.length === 0 && <option value="">No SIP accounts</option>}
              {sipAccounts.map(account => (
                <option key={account.id} value={account.id}>
                  {account.label || `${account.server_type.toUpperCase()} @ ${account.server_host}`}
                </option>
              ))}
            </select>
          </div>

          <div className="rounded-lg border border-gray-200 dark:border-gray-700 p-4 space-y-2">
            <p className="text-sm text-gray-700 dark:text-gray-200">
              Status: <span className="font-semibold">{callStatus.replace('_', ' ')}</span>
            </p>
            {callError && <p className="text-sm text-red-500">{callError}</p>}
            <div className="flex gap-3">
              <button
                onClick={startCall}
                disabled={callStatus === 'connecting' || callStatus === 'ringing' || callStatus === 'in_call'}
                className="inline-flex items-center justify-center rounded-md border border-transparent bg-green-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-green-700 disabled:opacity-50"
              >
                Call Now
              </button>
              <button
                onClick={hangupCall}
                disabled={callStatus !== 'ringing' && callStatus !== 'in_call'}
                className="inline-flex items-center justify-center rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 shadow-sm hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
              >
                Hang Up
              </button>
            </div>
          </div>

          <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
            <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">Call History</h4>
            {callLogs.length === 0 ? (
              <p className="text-sm text-gray-500 dark:text-gray-400">No calls logged yet.</p>
            ) : (
              <div className="space-y-2">
                {callLogs.slice(0, 5).map(log => (
                  <div key={log.id} className="flex items-center justify-between text-sm text-gray-600 dark:text-gray-300">
                    <span>{new Date(log.started_at).toLocaleString()}</span>
                    <span className="font-medium">{log.status}</span>
                    <span>{log.duration_seconds || 0}s</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </Modal>

      {/* Emergency Contact Modal */}
      <Modal
        isOpen={isEmergencyModalOpen}
        onClose={() => {
          setIsEmergencyModalOpen(false);
          setEmergencyContactTarget(null);
          setIsEditingEmergency(false);
          setEditingEmergencyId(null);
          setEmergencyError('');
        }}
        title={`${isEditingEmergency ? 'Edit' : 'Add'} Emergency Contact${emergencyContactTarget ? ` for ${emergencyContactTarget.name}` : ''}`}
      >
        <form onSubmit={handleEmergencySave} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Name</label>
            <input
              type="text"
              required
              className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              value={emergencyForm.name}
              onChange={(e) => setEmergencyForm({ ...emergencyForm, name: e.target.value })}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Phone</label>
            <input
              type="tel"
              required
              className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              value={emergencyForm.phone}
              onChange={(e) => setEmergencyForm({ ...emergencyForm, phone: e.target.value })}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Email</label>
            <input
              type="email"
              required
              className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              value={emergencyForm.email}
              onChange={(e) => setEmergencyForm({ ...emergencyForm, email: e.target.value })}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Relationship</label>
            <select
              className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm p-2 border bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              value={emergencyForm.relationship}
              onChange={(e) => setEmergencyForm({ ...emergencyForm, relationship: e.target.value })}
            >
              {relationshipOptions.map(option => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
          </div>
          {emergencyError && <p className="text-sm text-red-500">{emergencyError}</p>}
          <div className="flex justify-end gap-3 mt-5">
            <button
              type="button"
              onClick={() => {
                setIsEmergencyModalOpen(false);
                setEmergencyContactTarget(null);
              }}
              className="inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 shadow-sm hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="inline-flex justify-center rounded-md border border-transparent bg-primary-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2"
            >
              {isEditingEmergency ? 'Update' : 'Save'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={isDeleteModalOpen}
        onClose={() => setIsDeleteModalOpen(false)}
        title="Delete Contact"
      >
         <div className="flex flex-col items-center text-center">
            <div className="bg-red-100 dark:bg-red-900/30 p-3 rounded-full mb-4">
                <AlertTriangle className="w-8 h-8 text-red-600 dark:text-red-400" />
            </div>
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Are you sure?</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
                This action cannot be undone. This will permanently delete the contact from your directory.
            </p>
            <div className="flex gap-3 w-full">
                <button
                    onClick={() => setIsDeleteModalOpen(false)}
                    className="flex-1 justify-center rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 shadow-sm hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2"
                >
                    Cancel
                </button>
                <button
                    onClick={confirmDelete}
                    className="flex-1 justify-center rounded-md border border-transparent bg-red-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2"
                >
                    Delete
                </button>
            </div>
        </div>
      </Modal>

      {/* Import Modal */}
      <Modal
        isOpen={isImportModalOpen}
        onClose={() => {
          if (!importProgress.isImporting) {
            setIsImportModalOpen(false);
            // Reset progress state when closing
            setImportProgress({
              isImporting: false,
              current: 0,
              total: 0,
              status: 'parsing',
              message: '',
            });
          }
        }}
        title="Import Contacts"
      >
        <div className="space-y-4">
          {!importProgress.isImporting ? (
            // File upload interface
            <>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Upload CSV or Excel File
                </label>
                <div className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 text-center">
                  <Upload className="mx-auto h-12 w-12 text-gray-400 mb-4" />
                  <input
                    type="file"
                    accept=".csv,.xlsx,.xls"
                    onChange={handleFileImport}
                    className="hidden"
                    id="file-import"
                    disabled={importProgress.isImporting}
                  />
                  <label
                    htmlFor="file-import"
                    className={`cursor-pointer inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 shadow-sm text-sm font-medium rounded-md ${
                      importProgress.isImporting
                        ? 'text-gray-400 bg-gray-100 dark:bg-gray-700 cursor-not-allowed'
                        : 'text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500'
                    }`}
                  >
                    <Upload className="w-4 h-4 mr-2" />
                    Choose File
                  </label>
                </div>
              </div>

              <div className="text-sm text-gray-600 dark:text-gray-400">
                <p className="font-medium mb-2">Supported formats:</p>
                <ul className="list-disc list-inside space-y-1 ml-4">
                  <li>CSV files (.csv)</li>
                  <li>Excel files (.xlsx, .xls)</li>
                </ul>
                <p className="mt-3 text-xs">
                  Expected format: name,phone,address (CSV with headers)
                </p>
              </div>
            </>
          ) : (
            // Progress and completion interface
            <div className="space-y-4">
              {/* Progress Bar */}
              <div>
                <div className="flex justify-between items-center mb-2">
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                    {importProgress.status === 'parsing' && 'Reading file...'}
                    {importProgress.status === 'uploading' && `Importing ${importProgress.current} of ${importProgress.total} contacts...`}
                    {importProgress.status === 'completed' && 'Import completed!'}
                    {importProgress.status === 'error' && 'Import failed'}
                  </span>
                  {importProgress.total > 0 && (
                    <span className="text-sm text-gray-500">
                      {Math.round((importProgress.current / importProgress.total) * 100)}%
                    </span>
                  )}
                </div>
                
                {importProgress.total > 0 && (
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div 
                      className={`h-2 rounded-full transition-all duration-300 ${
                        importProgress.status === 'completed' 
                          ? 'bg-green-500' 
                          : importProgress.status === 'error'
                          ? 'bg-red-500'
                          : 'bg-blue-500'
                      }`}
                      style={{ width: `${(importProgress.current / importProgress.total) * 100}%` }}
                    />
                  </div>
                )}
              </div>

              {/* Status Message */}
              <div className={`text-center p-4 rounded-lg ${
                  importProgress.status === 'completed' 
                    ? 'bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800' 
                    : importProgress.status === 'error'
                    ? 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800'
                    : 'bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800'
                }`}>
                  <p className="text-sm text-gray-700 dark:text-gray-200">
                    {importProgress.message}
                  </p>
              </div>

              {/* Results Summary */}
              {importProgress.status === 'completed' && importProgress.results && (
                <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4 space-y-2">
                  <h4 className="font-medium text-gray-900 dark:text-white mb-3">Import Summary</h4>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div className="flex items-center">
                      <span className="text-green-600 dark:text-green-400 font-medium">✓ {importProgress.results.successful}</span>
                      <span className="text-gray-600 dark:text-gray-400 ml-2">Successfully imported</span>
                    </div>
                    <div className="flex items-center">
                      <span className="text-red-600 dark:text-red-400 font-medium">✗ {importProgress.results.failed}</span>
                      <span className="text-gray-600 dark:text-gray-400 ml-2">Failed to import</span>
                    </div>
                    <div className="flex items-center">
                      <span className="text-yellow-600 dark:text-yellow-400 font-medium">⚠ {importProgress.results.duplicates}</span>
                      <span className="text-gray-600 dark:text-gray-400 ml-2">Duplicates found</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Action Buttons */}
              <div className="flex justify-end gap-3">
                {importProgress.status === 'error' && (
                  <button
                    onClick={() => {
                      setImportProgress({
                        isImporting: false,
                        current: 0,
                        total: 0,
                        status: 'parsing',
                        message: '',
                      });
                    }}
                    className="inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 shadow-sm hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2"
                  >
                    Try Again
                  </button>
                )}
                {importProgress.status === 'completed' && (
                  <button
                    onClick={() => {
                      setIsImportModalOpen(false);
                      setImportProgress({
                        isImporting: false,
                        current: 0,
                        total: 0,
                        status: 'parsing',
                        message: '',
                      });
                    }}
                    className="inline-flex justify-center rounded-md border border-transparent bg-green-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2"
                  >
                    Done
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
};

export default Contacts;
