import React, { useState, useEffect } from 'react';
import { Secret, SecretPayload, SecretCategory, CustomCategory } from '../types';
import * as secretService from '../services/secretService';
import Modal from '../components/Modal';
import { Search, Plus, Trash2, Key, Database, Globe, FileText, Copy, Eye, EyeOff, Loader2, Lock, AlertTriangle, Share2, Check, Tag, Settings, X } from 'lucide-react';
import { canDelete as canDeleteForRole, canManageCategories as canManageCategoriesForRole, canModify as canModifyForRole, canShare as canShareForRole, getRole } from '../utils/permissions';

const DEFAULT_CATEGORIES = [
  { id: 'general', label: 'General', icon: FileText, color: 'bg-orange-100 text-orange-800', darkColor: 'dark:bg-orange-900/50 dark:text-orange-200' },
  { id: 'password', label: 'Password', icon: Lock, color: 'bg-blue-100 text-blue-800', darkColor: 'dark:bg-blue-900/50 dark:text-blue-200' },
  { id: 'api', label: 'API Key', icon: Key, color: 'bg-purple-100 text-purple-800', darkColor: 'dark:bg-purple-900/50 dark:text-purple-200' },
  { id: 'database', label: 'Database', icon: Database, color: 'bg-green-100 text-green-800', darkColor: 'dark:bg-green-900/50 dark:text-green-200' },
];

const SECRET_TYPE_CONFIGS = {
  'personal_access_token': {
    label: 'Personal Access Token',
    fields: ['title', 'token', 'notes'],
    optionalFields: ['expiration_date', 'environment_tags'],
    metadata: { expiration_date: true, environment_tags: true, access_scope: false },
    validation: {
      pat_token: { pattern: /^[a-zA-Z0-9_\-\.]{20,}$/, message: 'Invalid Personal Access Token format' }
    },
    placeholders: {
      token: 'pat_xxxxx',
      notes: 'Personal Access Token with specific permissions and scope (e.g., GitHub PAT, DigitalOcean PAT, GitLab PAT)'
    }
  },
  'api_token': {
    label: 'API Token',
    fields: ['title', 'token', 'notes'],
    optionalFields: ['expiration_date', 'environment_tags'],
    metadata: { expiration_date: true, environment_tags: true, access_scope: false },
    validation: {
      api_token: { pattern: /^[a-zA-Z0-9_\-\.]{20,}$/, message: 'Invalid API Token format' }
    },
    placeholders: {
      token: 'api_token_xxxxx',
      notes: 'API Token for service authentication (e.g., OpenAI API, Stripe API, AWS API Key)'
    }
  },
  'password': {
    label: 'Password',
    fields: ['title', 'username', 'password', 'url', 'notes'],
    optionalFields: ['expiration_date', 'environment_tags'],
    metadata: { expiration_date: true, environment_tags: true, access_scope: false },
    validation: {
      password: { required: true, message: 'Password is required' }
    },
    placeholders: {
      password: 'enter-secure-password',
      url: 'e.g., https://example.com',
      notes: 'Add any additional context or usage instructions'
    }
  },
  'database': {
    label: 'Database Connection',
    fields: ['title', 'connection_string', 'notes'],
    optionalFields: ['expiration_date', 'environment_tags'],
    metadata: { expiration_date: true, environment_tags: true, access_scope: false },
    validation: {
      connection_string: { required: true, message: 'Connection string is required' }
    },
    placeholders: {
      connection_string: 'e.g., mongodb://user:pass@host:port/db',
      notes: 'Database type, connection parameters, etc.'
    }
  },
  'private_key': {
    label: 'Private Key',
    fields: ['title', 'key_data', 'notes'],
    optionalFields: ['expiration_date', 'access_scope'],
    metadata: { expiration_date: true, environment_tags: false, access_scope: true },
    validation: {
      key_data: { pattern: /^-----BEGIN.*PRIVATE KEY-----/, message: 'Invalid private key format' }
    },
    placeholders: {
      key_data: '-----BEGIN PRIVATE KEY-----\n...',
      notes: 'PEM format private key content'
    }
  },
  'aws_credentials': {
    label: 'AWS Credentials',
    fields: ['title', 'access_key_id', 'secret_access_key', 'region', 'notes'],
    optionalFields: ['expiration_date', 'environment_tags', 'access_scope'],
    metadata: { expiration_date: true, environment_tags: true, access_scope: true },
    validation: {
      access_key_id: { pattern: /^[A-Z0-9]{20}$/, message: 'Invalid AWS Access Key ID format' },
      secret_access_key: { pattern: /^[a-zA-Z0-9\/+]{40}$/, message: 'Invalid AWS Secret Access Key format' }
    },
    placeholders: {
      access_key_id: 'AKIAJxxxxx',
      secret_access_key: 'xxxxx',
      region: 'e.g., us-east-1, eu-west-2',
      notes: 'IAM permissions, associated services, etc.'
    }
  },
  'encryption_key': {
    label: 'Encryption Key',
    fields: ['title', 'key_value', 'algorithm', 'notes'],
    optionalFields: ['expiration_date', 'environment_tags'],
    metadata: { expiration_date: true, environment_tags: true, access_scope: false },
    validation: {
      key_value: { required: true, message: 'Key value is required' }
    },
    placeholders: {
      key_value: 'base64-encoded-key-value',
      algorithm: 'e.g., AES-256, RSA-2048',
      notes: 'Encryption algorithm and key size'
    }
  },
  'github_token': {
    label: 'GitHub Token',
    fields: ['title', 'token', 'username', 'notes'],
    optionalFields: ['expiration_date', 'environment_tags'],
    metadata: { expiration_date: true, environment_tags: true, access_scope: false },
    validation: {
      token: { pattern: /^ghp_[a-zA-Z0-9]{36}$/, message: 'Invalid GitHub personal access token format' }
    },
    placeholders: {
      token: 'ghp_xxxxx',
      username: 'GitHub username',
      notes: 'Repository permissions, token scope, etc.'
    }
  },
  'gitlab_token': {
    label: 'GitLab Token',
    fields: ['title', 'token', 'instance_url', 'notes'],
    optionalFields: ['expiration_date', 'environment_tags'],
    metadata: { expiration_date: true, environment_tags: true, access_scope: false },
    validation: {
      token: { pattern: /^glpat-[a-zA-Z0-9\-_]{20}$/, message: 'Invalid GitLab personal access token format' }
    },
    placeholders: {
      token: 'glpat_xxxxx',
      instance_url: 'e.g., https://gitlab.com',
      notes: 'Project permissions, token scope, etc.'
    }
  }
};

const Secrets: React.FC = () => {
  const role = getRole();
  const canModify = canModifyForRole(role);
  const canDelete = canDeleteForRole(role);
  const canManageCategories = canManageCategoriesForRole(role);
  const canShare = canShareForRole(role);

  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [customCategories, setCustomCategories] = useState<CustomCategory[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isViewModalOpen, setIsViewModalOpen] = useState(false);
  const [currentSecret, setCurrentSecret] = useState<Partial<Secret>>({});
  const [viewSecretData, setViewSecretData] = useState<Secret | null>(null);
  const [showPassword, setShowPassword] = useState(false);

  // Category Management State
  const [isCategoryModalOpen, setIsCategoryModalOpen] = useState(false);
  const [newCategoryName, setNewCategoryName] = useState('');
  const [categoryLoading, setCategoryLoading] = useState(false);

  // Share Modal State
  const [isShareModalOpen, setIsShareModalOpen] = useState(false);
  const [shareConfig, setShareConfig] = useState({ expiresInMinutes: 60, maxViews: 1 });
  const [generatedLink, setGeneratedLink] = useState('');
  const [sharingLoading, setSharingLoading] = useState(false);

  // Delete Confirmation State
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [secretToDelete, setSecretToDelete] = useState<number | null>(null);

  const fetchSecrets = async () => {
    setLoading(true);
    try {
      const data = await secretService.getSecrets(searchTerm, categoryFilter);
      setSecrets(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const fetchCategories = async () => {
      try {
          const cats = await secretService.getCustomCategories();
          setCustomCategories(cats);
      } catch (e) {
          console.error('Failed to load categories');
      }
  };

  useEffect(() => {
    fetchCategories();
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchSecrets();
    }, 300);
    return () => clearTimeout(timer);
  }, [searchTerm, categoryFilter]);

  // Combine default and custom categories
  const allCategories = [
      ...DEFAULT_CATEGORIES,
      ...customCategories.map(c => ({
          id: c.id,
          label: c.label,
          icon: Tag,
          color: 'bg-teal-100 text-teal-800',
          darkColor: 'dark:bg-teal-900/50 dark:text-teal-200'
      }))
  ];

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canModify) return;
    try {
      const payload = currentSecret as SecretPayload;
      if (currentSecret.id) {
        await secretService.updateSecret(currentSecret.id, payload);
      } else {
        await secretService.createSecret(payload);
      }
      setIsEditModalOpen(false);
      fetchSecrets();
    } catch (err) {
      alert('Failed to save secret');
    }
  };

  const handleAddCategory = async (e: React.FormEvent) => {
      e.preventDefault();
      if (!canManageCategories) return;
      if (!newCategoryName.trim()) return;
      setCategoryLoading(true);
      try {
          await secretService.createCustomCategory(newCategoryName);
          setNewCategoryName('');
          fetchCategories();
      } catch(e: any) {
          alert(e.error || 'Failed to add category');
      } finally {
          setCategoryLoading(false);
      }
  };

  const handleDeleteCategory = async (id: string) => {
      if (!canDelete) return;
      if(!window.confirm('Are you sure? Secrets in this category will not be deleted but may display as Uncategorized.')) return;
      try {
          await secretService.deleteCustomCategory(id);
          fetchCategories();
      } catch(e) {
          alert('Failed to delete category');
      }
  };

  const initiateDelete = (id: number) => {
    if (!canDelete) return;
    setSecretToDelete(id);
    setIsDeleteModalOpen(true);
  };

  const confirmDelete = async () => {
    if (secretToDelete === null) return;
    if (!canDelete) return;
    try {
      await secretService.deleteSecret(secretToDelete);
      fetchSecrets();
    } catch (err) {
      alert('Failed to delete');
    } finally {
        setIsDeleteModalOpen(false);
        setSecretToDelete(null);
    }
  };

  const handleView = async (id: number) => {
    try {
      const data = await secretService.getSecretDetails(id);
      setViewSecretData(data);
      setShowPassword(false);
      setIsViewModalOpen(true);
    } catch (err) {
      alert('Could not fetch details');
    }
  };

  const openAdd = () => {
    if (!canModify) return;
    setCurrentSecret({ title: '', category: 'general', notes: '' });
    setIsEditModalOpen(true);
  };

  const openEdit = async (id: number) => {
      if (!canModify) return;
      try {
        const data = await secretService.getSecretDetails(id);
        setCurrentSecret(data);
        setIsEditModalOpen(true);
      } catch(e) {
          console.error(e);
      }
  }

  const openShare = async (id: number) => {
      if (!canShare) return;
      // Fetch details first to ensure it exists
      try {
          const data = await secretService.getSecretDetails(id);
          setCurrentSecret(data); // Set current secret for context
          setGeneratedLink(''); // Reset previous link
          setShareConfig({ expiresInMinutes: 60, maxViews: 1 }); // Reset defaults
          setIsShareModalOpen(true);
      } catch (e) {
          console.error(e);
          alert('Error preparing share');
      }
  }

  const generateShareLink = async () => {
      if (!currentSecret.id) return;
      if (!canShare) return;
      setSharingLoading(true);
      try {
          const result = await secretService.createShareLink(currentSecret.id, shareConfig);
          setGeneratedLink(result.link);
      } catch(e) {
          alert('Failed to generate link');
      } finally {
          setSharingLoading(false);
      }
  }

  const copyToClipboard = (text?: string) => {
    if (text) {
      navigator.clipboard.writeText(text);
      alert('Copied to clipboard!');
    }
  };

  const getCategoryMeta = (cat: string) => {
      const found = allCategories.find(c => c.id === cat);
      if (found) return found;
      // Fallback for deleted or unknown categories
      return { id: cat, label: cat || 'Unknown', icon: Tag, color: 'bg-gray-100 text-gray-800', darkColor: 'dark:bg-gray-700 dark:text-gray-300' };
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Secrets</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Securely store passwords, API keys, and notes.</p>
        </div>
        <div className="flex gap-2 w-full sm:w-auto">
            {canManageCategories && (
              <button
              onClick={() => setIsCategoryModalOpen(true)}
              className="flex-1 sm:flex-none inline-flex items-center justify-center px-4 py-2 border border-gray-300 dark:border-gray-600 shadow-sm text-sm font-medium rounded-md text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
              >
              <Settings className="w-4 h-4 mr-2" />
              Manage Categories
              </button>
            )}
            {canModify && (
              <button
              onClick={openAdd}
              className="flex-1 sm:flex-none inline-flex items-center justify-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
              >
              <Plus className="w-4 h-4 mr-2" />
              Add Secret
              </button>
            )}
        </div>
      </div>

      <div className="space-y-4">
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <Search className="h-5 w-5 text-gray-400" />
          </div>
          <input
            type="text"
            className="block w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg leading-5 bg-white dark:bg-gray-800 placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-primary-500 focus:border-primary-500 sm:text-sm text-gray-900 dark:text-white shadow-sm"
            placeholder="Search secrets by title, username, or notes..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        
        {/* Category Chips */}
        <div className="flex flex-wrap gap-2">
            <button
                onClick={() => setCategoryFilter('')}
                className={`inline-flex items-center px-3 py-1.5 rounded-full text-sm font-medium transition-colors ${
                    categoryFilter === ''
                    ? 'bg-primary-600 text-white shadow-sm'
                    : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700'
                }`}
            >
                All
            </button>
            {allCategories.map(c => (
                <button
                    key={c.id}
                    onClick={() => setCategoryFilter(categoryFilter === c.id ? '' : c.id)}
                    className={`inline-flex items-center px-3 py-1.5 rounded-full text-sm font-medium transition-colors ${
                        categoryFilter === c.id
                        ? 'bg-primary-600 text-white shadow-sm'
                        : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700'
                    }`}
                >
                    {c.label}
                </button>
            ))}
        </div>
      </div>

      {loading ? (
        <div className="flex justify-center py-12">
          <Loader2 className="w-8 h-8 animate-spin text-primary-600" />
        </div>
      ) : secrets.length === 0 ? (
        <div className="text-center py-12 bg-white dark:bg-gray-800 rounded-lg border border-dashed border-gray-300 dark:border-gray-700">
           <Lock className="mx-auto h-12 w-12 text-gray-400" />
           <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No secrets stored</h3>
           <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">Keep your sensitive data safe here.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {secrets.map((secret) => {
            const meta = getCategoryMeta(secret.category);
            const Icon = meta.icon;
            return (
              <div key={secret.id} className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg hover:shadow-md transition-shadow duration-200 border border-gray-100 dark:border-gray-700 flex flex-col">
                <div className="p-5 flex-1">
                  <div className="flex items-center">
                    <div className={`flex-shrink-0 rounded-md p-3 ${meta.color} ${meta.darkColor}`}>
                      <Icon className="h-6 w-6" />
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">{meta.label}</dt>
                        <dd>
                          <div className="text-lg font-medium text-gray-900 dark:text-white truncate" title={secret.title}>{secret.title}</div>
                        </dd>
                      </dl>
                    </div>
                  </div>
                  <div className="mt-4">
                      {secret.username && <p className="text-sm text-gray-600 dark:text-gray-300 flex items-center gap-1 mb-1"><span className="font-semibold">User:</span> {secret.username}</p>}
                      {secret.url && <a href={secret.url} target="_blank" rel="noreferrer" className="text-sm text-primary-600 dark:text-primary-400 hover:underline flex items-center gap-1 truncate"><Globe className="w-3 h-3"/> {secret.url}</a>}
                  </div>
                </div>
                <div className="bg-gray-50 dark:bg-gray-900/50 px-5 py-3 border-t border-gray-100 dark:border-gray-700 flex justify-between items-center">
                  <button onClick={() => handleView(secret.id)} className="text-sm text-primary-600 dark:text-primary-400 font-medium hover:text-primary-900 dark:hover:text-primary-300">
                    View Details
                  </button>
                  <div className="flex gap-2">
                    {canShare && (
                      <button onClick={() => openShare(secret.id)} className="text-gray-400 hover:text-blue-600 dark:hover:text-blue-400" title="Share">
                          <Share2 className="w-4 h-4" />
                      </button>
                    )}
                    {canModify && (
                      <button onClick={() => openEdit(secret.id)} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300" title="Edit">
                          <Key className="w-4 h-4" />
                      </button>
                    )}
                    {canDelete && (
                      <button onClick={() => initiateDelete(secret.id)} className="text-gray-400 hover:text-red-600 dark:hover:text-red-400" title="Delete">
                          <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Add/Edit Modal */}
      <Modal isOpen={isEditModalOpen} onClose={() => setIsEditModalOpen(false)} title={currentSecret.id ? 'Edit Secret' : 'Add Secret'}>
        <form onSubmit={handleSave} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Title *</label>
            <input type="text" required className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 border p-2 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              value={currentSecret.title || ''} onChange={(e) => setCurrentSecret({ ...currentSecret, title: e.target.value })} />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Category</label>
            <select className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 border p-2 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              value={currentSecret.category || 'general'} onChange={(e) => setCurrentSecret({ ...currentSecret, category: e.target.value as SecretCategory })}>
              {allCategories.map(c => <option key={c.id} value={c.id}>{c.label}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Username / Email</label>
            <input type="text" className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 border p-2 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              value={currentSecret.username || ''} onChange={(e) => setCurrentSecret({ ...currentSecret, username: e.target.value })} />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Password</label>
            <div className="relative rounded-md shadow-sm">
                <input type={showPassword ? "text" : "password"} className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 border p-2 pr-10 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                value={currentSecret.password || ''} onChange={(e) => setCurrentSecret({ ...currentSecret, password: e.target.value })} />
                 <div className="absolute inset-y-0 right-0 pr-3 flex items-center cursor-pointer" onClick={() => setShowPassword(!showPassword)}>
                     {showPassword ? <EyeOff className="h-4 w-4 text-gray-400" /> : <Eye className="h-4 w-4 text-gray-400" />}
                 </div>
            </div>
          </div>
          {currentSecret.category === 'api' && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">API Key</label>
                <input type="text" className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 border p-2 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  value={currentSecret.api_key || ''} onChange={(e) => setCurrentSecret({ ...currentSecret, api_key: e.target.value })} />
              </div>
          )}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">URL</label>
            <input type="url" className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 border p-2 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              value={currentSecret.url || ''} onChange={(e) => setCurrentSecret({ ...currentSecret, url: e.target.value })} />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Notes</label>
            <textarea rows={3} className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 border p-2 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              value={currentSecret.notes || ''} onChange={(e) => setCurrentSecret({ ...currentSecret, notes: e.target.value })} />
          </div>
          <div className="flex justify-end gap-3 pt-4">
            <button type="button" onClick={() => setIsEditModalOpen(false)} className="px-4 py-2 border dark:border-gray-600 rounded-md text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-600">Cancel</button>
            <button type="submit" className="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700">Save</button>
          </div>
        </form>
      </Modal>

      {/* Manage Categories Modal */}
      <Modal isOpen={isCategoryModalOpen} onClose={() => setIsCategoryModalOpen(false)} title="Manage Categories">
          <div className="space-y-6">
              {canManageCategories && (
                <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Add New Category</label>
                    <form onSubmit={handleAddCategory} className="flex gap-2">
                        <input 
                          type="text" 
                          required
                          placeholder="e.g. Finance"
                          className="flex-1 rounded-md border-gray-300 dark:border-gray-600 border p-2 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                          value={newCategoryName}
                          onChange={(e) => setNewCategoryName(e.target.value)}
                        />
                        <button 
                          type="submit" 
                          disabled={categoryLoading || !newCategoryName.trim()}
                          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-primary-600 hover:bg-primary-700 focus:outline-none disabled:opacity-50"
                        >
                            {categoryLoading ? <Loader2 className="animate-spin h-4 w-4" /> : 'Add'}
                        </button>
                    </form>
                </div>
              )}

              <div>
                  <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Custom Categories</h4>
                  {customCategories.length === 0 ? (
                      <p className="text-sm text-gray-500 dark:text-gray-400 italic">No custom categories added yet.</p>
                  ) : (
                      <ul className="divide-y divide-gray-100 dark:divide-gray-700 bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700">
                          {customCategories.map(cat => (
                              <li key={cat.id} className="flex justify-between items-center p-3">
                                  <div className="flex items-center gap-2">
                                      <Tag className="w-4 h-4 text-teal-600 dark:text-teal-400" />
                                      <span className="text-sm text-gray-900 dark:text-white">{cat.label}</span>
                                  </div>
                                  {canDelete && (
                                    <button 
                                      onClick={() => handleDeleteCategory(cat.id)}
                                      className="text-gray-400 hover:text-red-500 transition-colors"
                                    >
                                        <Trash2 className="w-4 h-4" />
                                    </button>
                                  )}
                              </li>
                          ))}
                      </ul>
                  )}
              </div>
          </div>
      </Modal>

      {/* Share Modal */}
      <Modal isOpen={isShareModalOpen} onClose={() => setIsShareModalOpen(false)} title="Share Secret">
           {!generatedLink ? (
             <div className="space-y-4">
                 <p className="text-sm text-gray-500 dark:text-gray-400">
                     Generate a secure, temporary link to share this secret with others.
                 </p>
                 <div>
                     <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Expiration</label>
                     <select
                        className="mt-1 block w-full pl-3 pr-10 py-2 text-base border-gray-300 dark:border-gray-600 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                        value={shareConfig.expiresInMinutes}
                        onChange={(e) => setShareConfig({ ...shareConfig, expiresInMinutes: Number(e.target.value) })}
                     >
                         <option value={60}>1 Hour</option>
                         <option value={1440}>1 Day</option>
                         <option value={4320}>3 Days</option>
                         <option value={10080}>1 Week</option>
                     </select>
                 </div>
                 <div>
                     <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Max Views</label>
                     <select
                        className="mt-1 block w-full pl-3 pr-10 py-2 text-base border-gray-300 dark:border-gray-600 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                        value={shareConfig.maxViews}
                        onChange={(e) => setShareConfig({ ...shareConfig, maxViews: Number(e.target.value) })}
                     >
                         <option value={1}>1 View (Burn after reading)</option>
                         <option value={5}>5 Views</option>
                         <option value={10}>10 Views</option>
                         <option value={0}>Unlimited</option>
                     </select>
                 </div>
                 <div className="pt-4 flex justify-end">
                     <button 
                        onClick={generateShareLink} 
                        disabled={sharingLoading}
                        className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-primary-600 hover:bg-primary-700 focus:outline-none"
                     >
                        {sharingLoading ? <Loader2 className="animate-spin h-4 w-4 mr-2"/> : <Share2 className="h-4 w-4 mr-2" />}
                        Generate Link
                     </button>
                 </div>
             </div>
           ) : (
               <div className="space-y-4">
                   <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-md flex items-center mb-4">
                       <Check className="h-5 w-5 text-green-500 mr-2" />
                       <span className="text-sm text-green-800 dark:text-green-200">Link generated successfully!</span>
                   </div>
                   <div>
                       <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Share Link</label>
                       <div className="mt-1 flex rounded-md shadow-sm">
                           <input 
                              type="text" 
                              readOnly 
                              value={generatedLink}
                              className="flex-1 min-w-0 block w-full px-3 py-2 rounded-none rounded-l-md border border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-600 text-gray-500 dark:text-gray-200 sm:text-sm"
                           />
                           <button 
                              onClick={() => copyToClipboard(generatedLink)}
                              className="inline-flex items-center px-3 rounded-r-md border border-l-0 border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 text-gray-500 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-600"
                           >
                               <Copy className="h-4 w-4" />
                           </button>
                       </div>
                       <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
                           Anyone with this link can view the secret according to the limits you set.
                       </p>
                   </div>
                   <div className="pt-4 flex justify-end">
                       <button 
                          onClick={() => { setIsShareModalOpen(false); setGeneratedLink(''); }}
                          className="text-primary-600 hover:text-primary-500 font-medium text-sm"
                       >
                           Close
                       </button>
                   </div>
               </div>
           )}
      </Modal>

      {/* View Modal */}
      <Modal isOpen={isViewModalOpen} onClose={() => setIsViewModalOpen(false)} title="Secret Details">
        {viewSecretData && (
            <div className="space-y-4">
                <div className="flex items-center gap-2 mb-4 pb-4 border-b border-gray-100 dark:border-gray-700">
                    {(() => {
                        const meta = getCategoryMeta(viewSecretData.category);
                        const Icon = meta.icon;
                        return <Icon className={`h-6 w-6 ${meta.color.split(' ')[1]} ${meta.darkColor.split(' ')[1]}`} />;
                    })()}
                    <h2 className="text-xl font-bold text-gray-900 dark:text-white">{viewSecretData.title}</h2>
                </div>

                {viewSecretData.username && (
                    <div className="bg-gray-50 dark:bg-gray-700 p-3 rounded-md group relative">
                        <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase">Username</label>
                        <div className="flex justify-between items-center mt-1">
                             <span className="font-mono text-gray-900 dark:text-gray-100">{viewSecretData.username}</span>
                             <button onClick={() => copyToClipboard(viewSecretData.username)} className="text-gray-400 hover:text-primary-600 dark:hover:text-primary-400"><Copy className="w-4 h-4"/></button>
                        </div>
                    </div>
                )}

                {viewSecretData.password && (
                    <div className="bg-gray-50 dark:bg-gray-700 p-3 rounded-md">
                        <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase">Password</label>
                        <div className="flex justify-between items-center mt-1">
                             <span className="font-mono text-gray-900 dark:text-gray-100 break-all">{showPassword ? viewSecretData.password : '••••••••••••'}</span>
                             <div className="flex gap-2">
                                <button onClick={() => setShowPassword(!showPassword)} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
                                    {showPassword ? <EyeOff className="w-4 h-4"/> : <Eye className="w-4 h-4"/>}
                                </button>
                                <button onClick={() => copyToClipboard(viewSecretData.password)} className="text-gray-400 hover:text-primary-600 dark:hover:text-primary-400"><Copy className="w-4 h-4"/></button>
                             </div>
                        </div>
                    </div>
                )}

                {viewSecretData.api_key && (
                    <div className="bg-gray-50 dark:bg-gray-700 p-3 rounded-md">
                        <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase">API Key</label>
                        <div className="flex justify-between items-center mt-1">
                             <span className="font-mono text-gray-900 dark:text-gray-100 break-all">{showPassword ? viewSecretData.api_key : '••••••••••••'}</span>
                             <div className="flex gap-2">
                                <button onClick={() => setShowPassword(!showPassword)} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
                                    {showPassword ? <EyeOff className="w-4 h-4"/> : <Eye className="w-4 h-4"/>}
                                </button>
                                <button onClick={() => copyToClipboard(viewSecretData.api_key)} className="text-gray-400 hover:text-primary-600 dark:hover:text-primary-400"><Copy className="w-4 h-4"/></button>
                             </div>
                        </div>
                    </div>
                )}

                {viewSecretData.url && (
                    <div className="p-1">
                         <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase">URL</label>
                         <div className="mt-1">
                            <a href={viewSecretData.url} target="_blank" rel="noreferrer" className="text-primary-600 dark:text-primary-400 hover:underline flex items-center gap-1 break-all">
                                <Globe className="w-3 h-3"/> {viewSecretData.url}
                            </a>
                         </div>
                    </div>
                )}

                {viewSecretData.notes && (
                    <div className="p-1">
                        <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase">Notes</label>
                        <div className="mt-1 text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap bg-yellow-50 dark:bg-yellow-900/20 p-2 rounded border border-yellow-100 dark:border-yellow-900/30">
                            {viewSecretData.notes}
                        </div>
                    </div>
                )}
            </div>
        )}
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={isDeleteModalOpen}
        onClose={() => setIsDeleteModalOpen(false)}
        title="Delete Secret"
      >
         <div className="flex flex-col items-center text-center">
            <div className="bg-red-100 dark:bg-red-900/30 p-3 rounded-full mb-4">
                <AlertTriangle className="w-8 h-8 text-red-600 dark:text-red-400" />
            </div>
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Are you sure?</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
                This action cannot be undone. This will permanently delete this secret.
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

export default Secrets;
