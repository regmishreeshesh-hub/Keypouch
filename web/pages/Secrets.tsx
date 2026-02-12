import React, { useEffect, useMemo, useState } from 'react';
import { Secret, SecretPayload, CustomCategory } from '../types';
import * as secretService from '../services/secretService';
import * as encryptionService from '../services/encryptionService';
import Modal from '../components/Modal';
import SharingModal from '../components/SharingModal';
import PasswordGenerator from '../components/PasswordGenerator';
import SearchBar from '../components/ui/SearchBar';
import { Plus, Trash2, Key, Database, Globe, FileText, Loader2, Lock, ShieldCheck, Server, Layers, X, Share2, Copy, Check, Eye, EyeOff, Edit, ShieldAlert, Zap } from 'lucide-react';

const SECRET_TYPES = [
  { id: 'api_key', label: 'API Key / Token' },
  { id: 'password', label: 'Password' },
  { id: 'db_credentials', label: 'Database Credentials' },
  { id: 'ssl_cert', label: 'SSL Certificate' },
  { id: 'oauth_token', label: 'OAuth Token' },
  { id: 'ssh_key', label: 'SSH Key' },
  { id: 'private_key', label: 'Private Key' },
  { id: 'webhook', label: 'Webhook URL' },
  { id: 'general', label: 'General' },
];

const DEFAULT_CATEGORIES = [
  { id: 'api_key', label: 'API Key / Token' },
  { id: 'password', label: 'Password' },
  { id: 'db_credentials', label: 'Database Credentials' },
  { id: 'ssl_cert', label: 'SSL Certificate' },
  { id: 'oauth_token', label: 'OAuth Token' },
  { id: 'ssh_key', label: 'SSH Key' },
  { id: 'private_key', label: 'Private Key' },
  { id: 'webhook', label: 'Webhook URL' },
  { id: 'general', label: 'General' },
];

const searchSecretsInSecrets = (secrets: Secret[], query: string): Secret[] => {
  const tokens = query
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);

  if (tokens.length === 0) return secrets;

  return secrets.filter((secret) => {
    const haystack = [
      secret.title,
      secret.category,
      secret.username,
      secret.url,
      secret.notes,
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();

    return tokens.every((t) => haystack.includes(t));
  });
};

const Secrets: React.FC = () => {
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [currentSecret, setCurrentSecret] = useState<Partial<Secret>>({});
  const [customCategories, setCustomCategories] = useState<CustomCategory[]>([]);
  const [isAddingCategory, setIsAddingCategory] = useState(false);
  const [newCategoryLabel, setNewCategoryLabel] = useState('');
  const visibleSecrets = useMemo(() => searchSecretsInSecrets(secrets, searchTerm), [secrets, searchTerm]);

  const fetchSecrets = async () => {
    setLoading(true);
    try {
      const data = await secretService.getSecrets();
      const masterKey = await encryptionService.getMasterKey();

      if (masterKey) {
        const decryptedSecrets = await Promise.all(data.map(async (s) => {
          if (s.encrypted_content) {
            try {
              const decrypted = await encryptionService.decrypt(s.encrypted_content, s.content_iv!, s.content_auth_tag!, masterKey);
              if (decrypted) {
                const content = JSON.parse(decrypted);
                return { ...s, ...content };
              }
              return s;
            } catch (e) {
              console.error('Failed to decrypt secret', s.id, e);
              return s;
            }
          }
          return s;
        }));
        setSecrets(decryptedSecrets);
      } else {
        setSecrets(data);
      }
    } catch (error) {
      console.error('Failed to fetch secrets:', error);
      setSecrets([]);
    } finally {
      setLoading(false);
    }
  };


  const fetchCustomCategories = async () => {
    try {
      const data = await secretService.getCustomCategories();
      setCustomCategories(data);
    } catch (err) { console.error('Failed to fetch custom categories:', err); }
  };

  const handleAddCategory = async () => {
    if (!newCategoryLabel.trim()) {
      alert('Category name cannot be empty');
      return;
    }

    try {
      const newCategory = await secretService.createCustomCategory(newCategoryLabel);
      setCustomCategories([...customCategories, newCategory]);
      setNewCategoryLabel('');
      setIsAddingCategory(false);
      alert('Category created successfully');
    } catch (err: any) {
      alert(err.message || 'Failed to create category');
    }
  };

  useEffect(() => {
    fetchSecrets();
    fetchCustomCategories();
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const masterKey = await encryptionService.getMasterKey();
      if (!masterKey) throw new Error('Master key not found. Please re-login.');

      const secretData = {
        username: currentSecret.username,
        password: currentSecret.password,
        api_key: currentSecret.api_key,
        notes: currentSecret.notes,
      };

      const encrypted = await encryptionService.encrypt(JSON.stringify(secretData), masterKey);
      if (!encrypted) throw new Error('Encryption failed. Please try again.');

      const payload = {
        title: currentSecret.title,
        category: currentSecret.category,
        url: formatUrl(currentSecret.url),
        encrypted_content: encrypted.encrypted,
        content_iv: encrypted.iv,
        content_auth_tag: encrypted.authTag,
      } as any;

      if (currentSecret.id) await secretService.updateSecret(currentSecret.id, payload);
      else await secretService.createSecret(payload);

      setIsEditModalOpen(false);
      fetchSecrets();
    } catch (err: any) {
      alert(err.message || 'Failed to save');
    }
  };

  const openAdd = () => {
    setCurrentSecret({
      title: '',
      category: 'general',
      url: '',
      username: '',
      password: '',
      api_key: '',
      notes: ''
    });
    setIsAddingCategory(false);
    setNewCategoryLabel('');
    setIsEditModalOpen(true);
  };

  const formatUrl = (url: string | undefined): string => {
    if (!url) return '';
    let trimmed = url.trim();
    if (trimmed && !/^https?:\/\//i.test(trimmed)) {
      return `https://${trimmed}`;
    }
    return trimmed;
  };

  const handleUrlBlur = () => {
    const formatted = formatUrl(currentSecret.url);
    if (formatted !== currentSecret.url) {
      setCurrentSecret(prev => ({ ...prev, url: formatted }));
    }
  };

  const handleUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    let value = e.target.value;
    // Auto-prepend https:// if they start with www.
    if (value.toLowerCase().startsWith('www.') && !value.toLowerCase().startsWith('http')) {
      value = 'https://' + value;
    }
    setCurrentSecret(prev => ({ ...prev, url: value }));
  };

  const [isSharingModalOpen, setIsSharingModalOpen] = useState(false);
  const [currentShareSecret, setCurrentShareSecret] = useState<{ id: number; title: string; decryptedData: any } | null>(null);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [secretToDelete, setSecretToDelete] = useState<{ id: number; title: string } | null>(null);
  const [copiedId, setCopiedId] = useState<number | null>(null);
  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const [visiblePasswordId, setVisiblePasswordId] = useState<number | null>(null);
  const [showPasswordGenerator, setShowPasswordGenerator] = useState(false);

  const handleShareClick = (secret: Secret) => {
    setCurrentShareSecret({
      id: secret.id,
      title: secret.title,
      decryptedData: {
        username: secret.username,
        password: secret.password,
        api_key: secret.api_key,
        notes: secret.notes,
        url: secret.url,
      }
    });
    setIsSharingModalOpen(true);
  };

  const copyToClipboard = async (text: string, secretId: number, fieldName?: string) => {
    let copySuccessful = false;
    try {
      // Fallback for non-secure contexts (http://<ip>)
      if (!navigator.clipboard) {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.position = "fixed";
        textArea.style.left = "-999999px";
        textArea.style.top = "-999999px";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
          copySuccessful = document.execCommand('copy');
          textArea.remove();
        } catch (err) {
          console.error('Fallback copy failed', err);
          textArea.remove();
        }
      } else {
        await navigator.clipboard.writeText(text);
        copySuccessful = true;
      }

      if (copySuccessful) {
        setCopiedId(secretId);
        setCopyStatus(fieldName || 'Copied');
        setTimeout(() => {
          setCopiedId(null);
          setCopyStatus(null);
        }, 2000);

        // Clear clipboard after 60s
        setTimeout(() => {
          if (navigator.clipboard) {
            navigator.clipboard.writeText('');
          }
        }, 60000);

        // Log action (without content) - don't await to avoid blocking UI if logging fails
        secretService.logSecretAction('copy', secretId, { field: fieldName }).catch(console.error);
      } else {
        throw new Error('Copy command failed');
      }
    } catch (err) {
      console.error('Failed to copy!', err);
      alert('Copy failed. Your browser might be blocking clipboard access on this insecure connection (HTTP). Please try using HTTPS or copy manually.');
    }
  };


  const handleDeleteClick = (id: number, title: string) => {
    setSecretToDelete({ id, title });
    setIsDeleteModalOpen(true);
  };

  const confirmDelete = async () => {
    if (!secretToDelete) return;
    try {
      await secretService.deleteSecret(secretToDelete.id);
      setIsDeleteModalOpen(false);
      setSecretToDelete(null);
      fetchSecrets();
    } catch (err) {
      alert('Failed to delete secret');
    }
  };

  const openEdit = (secret: Secret) => {
    setCurrentSecret(secret);
    setIsEditModalOpen(true);
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold dark:text-white">Secrets</h1>
          <p className="text-xs text-gray-500 flex items-center gap-1.5 mt-1">
            <ShieldCheck className="w-3.5 h-3.5 text-green-500" />
            Zero-Knowledge AES-256 Protection Active
          </p>
        </div>
        <button onClick={openAdd} className="bg-primary-600 text-white px-4 py-2 rounded-md flex items-center gap-2 hover:bg-primary-700 transition-colors shadow-sm">
          <Plus className="w-4 h-4" /> Add Secret
        </button>
      </div>

      <SearchBar
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
        placeholder="Search secrets (title, user, URL, notes)..."
      />

      {loading ? <div className="flex justify-center p-12"><Loader2 className="animate-spin w-8 h-8 text-primary-600" /></div> : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {visibleSecrets.length === 0 && (
            <div className="col-span-full py-12 text-center bg-white dark:bg-gray-800 rounded-xl border border-dashed border-gray-300 dark:border-gray-700">
              <Lock className="w-12 h-12 text-gray-300 mx-auto mb-4" />
              <p className="text-gray-500 dark:text-gray-400">
                {searchTerm.trim() ? `No secrets match "${searchTerm.trim()}".` : 'No secrets found.'}
              </p>
            </div>
          )}
          {visibleSecrets.map(secret => (
            <div key={secret.id} className="bg-white dark:bg-gray-800 p-5 rounded-xl border dark:border-gray-700 shadow-sm hover:shadow-md transition-shadow">
              <div className="flex justify-between mb-4">
                <div className="flex items-center gap-2">
                  <div className="p-2 bg-primary-100 dark:bg-primary-900/30 rounded-lg">
                    <Lock className="w-4 h-4 text-primary-600 dark:text-primary-400" />
                  </div>
                  <div>
                    <h3 className="font-bold dark:text-white truncate max-w-[150px]">{secret.title}</h3>
                    <div className="flex items-center gap-1 text-gray-400">
                      <span className="text-[10px] uppercase font-semibold">{secret.category || 'general'}</span>
                    </div>
                  </div>
                </div>
                <div className="flex gap-1">
                  <button onClick={() => openEdit(secret)} className="p-1.5 text-gray-400 hover:text-primary-600 dark:hover:text-primary-400 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors">
                    <Edit className="w-4 h-4" />
                  </button>
                  <button onClick={() => handleDeleteClick(secret.id, secret.title)} className="p-1.5 text-gray-400 hover:text-red-600 dark:hover:text-red-400 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>

              <div className="space-y-3 mb-4 min-h-[100px]">
                {secret.username && (
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-gray-500">User</span>
                    <div className="flex items-center gap-2">
                      <span className="dark:text-gray-300 font-mono bg-gray-50 dark:bg-gray-900 px-1.5 py-0.5 rounded">{secret.username}</span>
                      <button onClick={() => copyToClipboard(secret.username!, secret.id, 'User copied')} className="text-gray-400 hover:text-primary-600">
                        {copiedId === secret.id && copyStatus === 'User copied' ? <Check className="w-3.5 h-3.5 text-green-500" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                )}

                {secret.password && (
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-gray-500">Secret</span>
                    <div className="flex items-center gap-2">
                      <span className="dark:text-gray-300 font-mono bg-gray-50 dark:bg-gray-900 px-1.5 py-0.5 rounded tracking-wider">
                        {visiblePasswordId === secret.id ? secret.password : '••••••••••••'}
                      </span>
                      <button onClick={() => setVisiblePasswordId(visiblePasswordId === secret.id ? null : secret.id)} className="text-gray-400 hover:text-gray-600">
                        {visiblePasswordId === secret.id ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                      <button onClick={() => copyToClipboard(secret.password!, secret.id, 'Pass copied')} className="text-gray-400 hover:text-primary-600">
                        {copiedId === secret.id && copyStatus === 'Pass copied' ? <Check className="w-3.5 h-3.5 text-green-500" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                )}

                {secret.api_key && (
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-gray-500">API Key</span>
                    <div className="flex items-center gap-2">
                      <span className="dark:text-gray-300 font-mono bg-gray-50 dark:bg-gray-900 px-1.5 py-0.5 rounded truncate max-w-[120px]">
                        {visiblePasswordId === secret.id ? secret.api_key : '••••••••••••'}
                      </span>
                      <button onClick={() => copyToClipboard(secret.api_key!, secret.id, 'Key copied')} className="text-gray-400 hover:text-primary-600">
                        {copiedId === secret.id && copyStatus === 'Key copied' ? <Check className="w-3.5 h-3.5 text-green-500" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                )}

                {secret.url && (
                  <div className="text-xs truncate text-primary-600 dark:text-primary-400 flex items-center gap-1.5 bg-primary-50 dark:bg-primary-900/10 p-2 rounded">
                    <Globe className="w-3.5 h-3.5" /> <span className="truncate">{secret.url}</span>
                  </div>
                )}

                {secret.notes && !secret.password && !secret.username && (
                  <div className="text-xs text-gray-500 line-clamp-3 bg-gray-50 dark:bg-gray-900 p-2 rounded italic">
                    {secret.notes}
                  </div>
                )}
              </div>
              <div className="flex justify-between items-center pt-4 border-t dark:border-gray-700">
                <div className="flex gap-2">
                  <button
                    onClick={() => handleShareClick(secret)}
                    className="flex items-center gap-1.5 text-primary-600 dark:text-primary-400 text-xs font-bold hover:bg-primary-50 dark:hover:bg-primary-900/20 px-2 py-1.5 rounded-md transition-colors"
                  >
                    <Share2 className="w-3.5 h-3.5" /> Share
                  </button>
                </div>
                <span className="text-[10px] text-gray-400">Modified: {new Date(secret.updated_at || secret.created_at!).toLocaleDateString()}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Share Modal */}
      {currentShareSecret && (
        <SharingModal
          isOpen={isSharingModalOpen}
          onClose={() => setIsSharingModalOpen(false)}
          secretId={currentShareSecret.id}
          secretTitle={currentShareSecret.title}
          decryptedData={currentShareSecret.decryptedData}
        />
      )}

      {/* Edit Modal */}
      <Modal isOpen={isEditModalOpen} onClose={() => setIsEditModalOpen(false)} title={currentSecret.id ? "Edit Secret" : "Add New Secret"}>
        <form onSubmit={handleSave} className="space-y-6">
          {/* Basic Information Section */}
          <div className="space-y-3 pb-6 border-b dark:border-gray-700">
            <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 uppercase flex items-center gap-2">
              <Key className="w-4 h-4" /> Basic Information
            </h3>
            <div className="grid gap-2">
              <label className="text-xs font-medium text-gray-500">Title</label>
              <input
                required
                placeholder="Secret Title (e.g., AWS Production API)"
                className="w-full p-2 border rounded dark:bg-gray-700 dark:text-white dark:border-gray-600"
                value={currentSecret.title || ''}
                onChange={e => setCurrentSecret({ ...currentSecret, title: e.target.value })}
              />
            </div>
          </div>

          {/* Categorization Section */}
          <div className="space-y-3 pb-6 border-b dark:border-gray-700">
            <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 uppercase flex items-center gap-2">
              <Layers className="w-4 h-4" /> Secret Type & Category
            </h3>

            <div>
              <label className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-2 block">Select Type or Category</label>
              {!isAddingCategory ? (
                <div className="flex gap-2">
                  <select
                    value={currentSecret.category || 'general'}
                    onChange={e => setCurrentSecret({ ...currentSecret, category: e.target.value })}
                    className="flex-1 p-2 border rounded dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm"
                  >
                    <optgroup label="Predefined Types">
                      {DEFAULT_CATEGORIES.map(cat => (
                        <option key={cat.id} value={cat.id}>{cat.label}</option>
                      ))}
                    </optgroup>
                    {customCategories.length > 0 && (
                      <optgroup label="Custom Categories">
                        {customCategories.map(cat => (
                          <option key={cat.id} value={cat.id}>{cat.label}</option>
                        ))}
                      </optgroup>
                    )}
                  </select>
                  <button
                    type="button"
                    onClick={() => setIsAddingCategory(true)}
                    className="px-3 py-2 bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-500 text-sm font-medium whitespace-nowrap"
                  >
                    + Custom
                  </button>
                </div>
              ) : (
                <div className="flex gap-2">
                  <input
                    autoFocus
                    placeholder="e.g., Production Secrets, Internal Tools..."
                    className="flex-1 p-2 border rounded dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm"
                    value={newCategoryLabel}
                    onChange={e => setNewCategoryLabel(e.target.value)}
                  />
                  <button
                    type="button"
                    onClick={handleAddCategory}
                    className="px-3 py-2 bg-primary-600 text-white rounded hover:bg-primary-700 text-sm font-medium whitespace-nowrap"
                  >
                    Add
                  </button>
                  <button
                    type="button"
                    onClick={() => { setIsAddingCategory(false); setNewCategoryLabel(''); }}
                    className="px-3 py-2 bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-500"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              )}
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                Create custom categories to organize secrets by team, project, or environment
              </p>
            </div>
          </div>

          {/* Secret Details Section */}
          <div className="space-y-3 pb-6 border-b dark:border-gray-700">
            <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 uppercase flex items-center gap-2">
              <Lock className="w-4 h-4" /> Secret Details
            </h3>

            <div>
              <label className="text-xs font-medium text-gray-500">Service URL</label>
              <input
                placeholder="URL (e.g., www.example.com)"
                className="w-full p-2 border rounded dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm"
                value={currentSecret.url || ''}
                onChange={handleUrlChange}
                onBlur={handleUrlBlur}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-xs font-medium text-gray-500">Username</label>
                <input
                  placeholder="Username / Identity"
                  className="w-full p-2 border rounded dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm"
                  value={currentSecret.username || ''}
                  onChange={e => setCurrentSecret({ ...currentSecret, username: e.target.value })}
                />
              </div>
              <div>
                <label className="text-xs font-medium text-gray-500">Password</label>
                <div className="relative">
                  <input
                    type="password"
                    placeholder="••••••••••••"
                    className="w-full p-2 border rounded dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm font-mono"
                    value={currentSecret.password || ''}
                    onChange={e => setCurrentSecret({ ...currentSecret, password: e.target.value })}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPasswordGenerator(!showPasswordGenerator)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-gray-400 hover:text-primary-600 dark:hover:text-primary-400"
                    title="Generate Strong Password"
                  >
                    <Zap className="w-4 h-4" />
                  </button>

                  {showPasswordGenerator && (
                    <div className="absolute top-12 right-0 z-50 w-full min-w-[300px] max-w-[350px]">
                      <PasswordGenerator
                        onSelectPassword={(password) => {
                          setCurrentSecret({ ...currentSecret, password: password });
                          setShowPasswordGenerator(false);
                        }}
                        onClose={() => setShowPasswordGenerator(false)}
                      />
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div>
              <label className="text-xs font-medium text-gray-500">API Key / Token</label>
              <input
                placeholder="sk_live_..."
                className="w-full p-2 border rounded dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm font-mono"
                value={currentSecret.api_key || ''}
                onChange={e => setCurrentSecret({ ...currentSecret, api_key: e.target.value })}
              />
            </div>
          </div>

          {/* Additional Information Section */}
          <div className="space-y-3 pb-6">
            <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 uppercase flex items-center gap-2">
              <FileText className="w-4 h-4" /> Additional Information
            </h3>
            <textarea
              placeholder="Notes..."
              className="w-full p-2 border rounded dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm"
              rows={3}
              value={currentSecret.notes || ''}
              onChange={e => setCurrentSecret({ ...currentSecret, notes: e.target.value })}
            />
          </div>

          <div className="flex gap-4">
            <button type="button" onClick={() => setIsEditModalOpen(false)} className="flex-1 py-2 rounded-md font-bold text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors">
              Cancel
            </button>
            <button type="submit" className="flex-1 bg-primary-600 text-white py-2 rounded-md font-bold hover:bg-primary-700 transition-colors shadow-sm">
              {currentSecret.id ? "Update Secret" : "Securely Save"}
            </button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal isOpen={isDeleteModalOpen} onClose={() => setIsDeleteModalOpen(false)} title="Confirm Deletion">
        <div className="space-y-6 py-4 text-center">
          <div className="mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-red-100 dark:bg-red-900/30">
            <ShieldAlert className="h-8 w-8 text-red-600 dark:text-red-400" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-gray-900 dark:text-white">Delete Secret?</h3>
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              Are you sure you want to delete <span className="font-bold text-gray-700 dark:text-gray-200">"{secretToDelete?.title}"</span>?
              This action cannot be undone and all active share links will be revoked.
            </p>
          </div>
          <div className="flex gap-4">
            <button
              onClick={() => setIsDeleteModalOpen(false)}
              className="flex-1 py-2.5 rounded-lg font-bold text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={confirmDelete}
              className="flex-1 py-2.5 rounded-lg font-bold text-white bg-red-600 hover:bg-red-700 transition-colors shadow-sm"
            >
              Delete Permanently
            </button>
          </div>
        </div>
      </Modal>
    </div >
  );
};

export default Secrets;
