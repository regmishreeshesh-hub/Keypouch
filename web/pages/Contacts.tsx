import React, { useState, useEffect } from 'react';
import { Contact, ContactPayload } from '../types';
import * as contactService from '../services/contactService';
import Modal from '../components/Modal';
import { Search, Plus, Edit2, Trash2, Download, Phone, MapPin, User, Loader2, AlertTriangle, Star, Zap, Save, X, Check } from 'lucide-react';
import { canDelete as canDeleteForRole, canModify as canModifyForRole, getRole } from '../utils/permissions';

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

  // Inline Edit State
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editForm, setEditForm] = useState<ContactPayload>({ name: '', phone: '', address: '', isFavorite: false });

  // Quick Add State
  const [showQuickAdd, setShowQuickAdd] = useState(false);
  const [quickAddData, setQuickAddData] = useState({ name: '', phone: '' });

  // Delete Confirmation State
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [contactToDelete, setContactToDelete] = useState<number | null>(null);

  const fetchContacts = async (search?: string) => {
    setLoading(true);
    try {
      const data = await contactService.getContacts(search);
      setContacts(data);
    } catch (err) {
      console.error(err);
      setError('Failed to fetch contacts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchContacts(searchTerm);
    }, 300);
    return () => clearTimeout(timer);
  }, [searchTerm]);

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

           <button
            onClick={handleExport}
            className="flex-1 sm:flex-none inline-flex items-center justify-center px-4 py-2 border border-gray-300 dark:border-gray-600 shadow-sm text-sm font-medium rounded-md text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
          >
            <Download className="w-4 h-4 mr-2" />
            Export
          </button>
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

            {displayedContacts.map((contact) => (
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
                  </div>
                )}
              </li>
            ))}
          </ul>
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
    </div>
  );
};

export default Contacts;
