import React, { useEffect, useState } from 'react';
import { User, AuditLog } from '../types';
import * as authService from '../services/authService';
import {
  Users,
  Loader2,
  Trash2,
  Shield,
  ShieldOff,
  AlertTriangle,
  Search,
  UserPlus,
  UserX,
  UserCheck,
  KeyRound,
  Edit2,
  RefreshCcw,
  LogOut,
  Eye,
  Lock
} from 'lucide-react';
import Modal from '../components/Modal';

const randomInt = (maxExclusive: number) => {
  if (maxExclusive <= 0) return 0;
  const cryptoObj: Crypto | undefined = (globalThis as any).crypto;
  if (cryptoObj?.getRandomValues) {
    const buf = new Uint32Array(1);
    cryptoObj.getRandomValues(buf);
    return buf[0] % maxExclusive;
  }
  return Math.floor(Math.random() * maxExclusive);
};

const shuffleInPlace = <T,>(arr: T[]) => {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
};

const generateTempPassword = (length = 12) => {
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const digits = '0123456789';
  // Avoid quotes/backslash for easier sharing.
  const symbols = '!@#$%^&*()-_=+[]{};:,.?';

  const all = lower + upper + digits + symbols;
  const n = Math.max(4, length);

  const chars = [
    lower[randomInt(lower.length)],
    upper[randomInt(upper.length)],
    digits[randomInt(digits.length)],
    symbols[randomInt(symbols.length)],
  ];

  while (chars.length < n) {
    chars.push(all[randomInt(all.length)]);
  }

  return shuffleInPlace(chars).join('');
};

const copyToClipboard = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const el = document.createElement('textarea');
      el.value = text;
      el.setAttribute('readonly', 'true');
      el.style.position = 'absolute';
      el.style.left = '-9999px';
      document.body.appendChild(el);
      el.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(el);
      return ok;
    } catch {
      return false;
    }
  }
};

const getRoleDisplay = (role: string) => {
  switch (role) {
    case 'admin': return 'Admin';
    case 'full-access': return 'Full Access';
    case 'modify': return 'Modify';
    case 'view': return 'View Only';
    default: return role;
  }
};

const AdminUsers: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [currentUser] = useState<string | null>(localStorage.getItem('username'));
  const [userToDelete, setUserToDelete] = useState<User | null>(null);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [createForm, setCreateForm] = useState({
    username: '',
    password: '',
    role: 'view' as 'admin' | 'full-access' | 'modify' | 'view',
    must_reset_password: true,
    is_disabled: false
  });
  const [createPwCopied, setCreatePwCopied] = useState(false);
  const [isCredsModalOpen, setIsCredsModalOpen] = useState(false);
  const [createdCreds, setCreatedCreds] = useState<{ username: string; password: string } | null>(null);
  const [credsCopied, setCredsCopied] = useState(false);

  const [isResetModalOpen, setIsResetModalOpen] = useState(false);
  const [resetUser, setResetUser] = useState<User | null>(null);
  const [resetPassword, setResetPassword] = useState('');

  const [isDetailsOpen, setIsDetailsOpen] = useState(false);
  const [detailsUser, setDetailsUser] = useState<User | null>(null);
  const [detailsLogs, setDetailsLogs] = useState<AuditLog[]>([]);
  const [detailsLoading, setDetailsLoading] = useState(false);

  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [editUser, setEditUser] = useState<User | null>(null);
  const [editForm, setEditForm] = useState({
    role: 'view' as 'admin' | 'full-access' | 'modify' | 'view',
    is_disabled: false,
    must_reset_password: false
  });

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const data = await authService.getUsers();
      setUsers(data);
      setError('');
    } catch (err: any) {
      setError(err.message || 'Failed to fetch users');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleRoleToggle = async (user: User) => {
    if (user.username === currentUser) {
      alert('You cannot edit your own role here. Use the Edit button.');
      return;
    }

    try {
      await authService.updateUserRole(user.id, user.role === 'admin' ? 'full-access' : 'admin');
      setUsers(users.map(u => (u.id === user.id ? { ...u, role: user.role === 'admin' ? 'full-access' : 'admin' } : u)));
    } catch (err: any) {
      alert('Failed to update role');
    }
  };

  const handleStatusToggle = async (user: User) => {
    const nextDisabled = !user.is_disabled;
    if (user.username === currentUser && nextDisabled) {
      if (!window.confirm('You are about to disable your own account. Continue?')) {
        return;
      }
    }
    try {
      const response = await authService.updateUserStatus(user.id, nextDisabled);
      setUsers(users.map(u => (u.id === user.id ? response.user : u)));
    } catch (err: any) {
      alert('Failed to update user status');
    }
  };

  const handleRevokeSessions = async (user: User) => {
    if (!window.confirm(`Revoke active sessions for ${user.username}?`)) return;
    try {
      await authService.revokeUserSessions(user.id);
      alert('Sessions revoked');
    } catch (err: any) {
      alert('Failed to revoke sessions');
    }
  };

  const handleResetMfa = async (user: User) => {
    if (!window.confirm(`Reset MFA for ${user.username}?`)) return;
    try {
      await authService.resetUserMfa(user.id);
      setUsers(users.map(u => (u.id === user.id ? { ...u, mfa_enabled: false } : u)));
    } catch (err: any) {
      alert('Failed to reset MFA');
    }
  };

  const openDetails = async (user: User) => {
    setIsDetailsOpen(true);
    setDetailsLoading(true);
    try {
      const detail = await authService.getUserDetails(user.id);
      const logs = await authService.getUserAuditLogs(user.id);
      setDetailsUser(detail);
      setDetailsLogs(logs);
    } catch (err: any) {
      alert('Failed to fetch user details');
      setIsDetailsOpen(false);
    } finally {
      setDetailsLoading(false);
    }
  };

  const openEdit = (user: User) => {
    setEditUser(user);
    setEditForm({
      role: user.role as 'admin' | 'full-access' | 'modify' | 'view',
      is_disabled: user.is_disabled || false,
      must_reset_password: user.must_reset_password || false
    });
    setIsEditModalOpen(true);
  };

  const handleEditUser = async () => {
    if (!editUser) return;

    try {
      const response = await authService.updateUser(editUser.id, editForm);
      setUsers(users.map(u => (u.id === editUser.id ? response.user : u)));
      setIsEditModalOpen(false);
      setEditUser(null);
    } catch (err: any) {
      alert('Failed to update user');
    }
  };

  const confirmDelete = async () => {
    if (!userToDelete) return;
    try {
      await authService.deleteUser(userToDelete.id);
      setUsers(users.filter(u => u.id !== userToDelete.id));
      setIsDeleteModalOpen(false);
      setUserToDelete(null);
    } catch (err: any) {
      alert('Failed to delete user');
    }
  };

  const initiateDelete = (user: User) => {
    setUserToDelete(user);
    setIsDeleteModalOpen(true);
  };

  const handleCreateUser = async () => {
    try {
      const password = createForm.password?.trim() ? createForm.password : generateTempPassword(12);
      const response = await authService.createUser({ ...createForm, password });
      setUsers([...users, response.user]);
      setIsCreateModalOpen(false);
      setCreatedCreds({ username: createForm.username, password });
      setIsCredsModalOpen(true);
      setCredsCopied(false);
      setCreateForm({ username: '', password: '', role: 'view', must_reset_password: true, is_disabled: false });
      setCreatePwCopied(false);
    } catch (err: any) {
      alert(err.message || 'Failed to create user');
    }
  };

  const openResetPassword = (user: User) => {
    setResetUser(user);
    setResetPassword('');
    setIsResetModalOpen(true);
  };

  const handleResetPassword = async () => {
    if (!resetUser) return;
    try {
      await authService.resetUserPassword(resetUser.id, resetPassword);
      setIsResetModalOpen(false);
      setResetUser(null);
      setResetPassword('');
      alert('Temporary password set');
    } catch (err: any) {
      alert('Failed to reset password');
    }
  };

  const filteredUsers = users.filter(user =>
    user.username.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">User Management</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Manage system access, security, and sessions.</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchUsers}
            className="p-2 rounded-md border border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-300 hover:text-primary-600 hover:border-primary-500 transition-colors"
            title="Refresh"
          >
            <RefreshCcw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => {
              setIsCreateModalOpen(true);
              const pw = generateTempPassword(12);
              setCreateForm({
                username: '',
                password: pw,
                role: 'view',
                must_reset_password: true,
                is_disabled: false
              });
              setCreatePwCopied(false);
            }}
            className="inline-flex items-center gap-2 rounded-md bg-primary-600 px-4 py-2 text-sm font-semibold text-white hover:bg-primary-700"
          >
            <UserPlus className="w-4 h-4" />
            Add User
          </button>
        </div>
      </div>

      <div className="relative">
        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <Search className="h-5 w-5 text-gray-400" />
        </div>
        <input
          type="text"
          className="block w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg leading-5 bg-white dark:bg-gray-800 placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-primary-500 focus:border-primary-500 sm:text-sm shadow-sm text-gray-900 dark:text-white"
          placeholder="Search users by username..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
      </div>

      {loading ? (
        <div className="flex justify-center py-12">
          <Loader2 className="w-8 h-8 animate-spin text-primary-600" />
        </div>
      ) : error ? (
        <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-md text-red-700 dark:text-red-300">
          {error}
        </div>
      ) : (
        <div className="bg-white dark:bg-gray-800 shadow overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-900">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  User
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Role
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  MFA
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Last Login
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Created
                </th>
                <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {filteredUsers.length > 0 ? (
                filteredUsers.map((user) => (
                  <tr key={user.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="flex-shrink-0 h-10 w-10 bg-primary-100 dark:bg-primary-900/50 rounded-full flex items-center justify-center">
                          <span className="text-primary-700 dark:text-primary-300 font-medium text-lg">
                            {user.username.charAt(0).toUpperCase()}
                          </span>
                        </div>
                        <div className="ml-4">
                          <div className="text-sm font-medium text-gray-900 dark:text-white">{user.username}</div>
                          <div className="text-xs text-gray-500 dark:text-gray-400">ID: {user.id}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        user.role === 'admin'
                          ? 'bg-purple-100 text-purple-800 dark:bg-purple-900/50 dark:text-purple-200'
                          : 'bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-200'
                      }`}>
                        {getRoleDisplay(user.role)}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        user.is_disabled
                          ? 'bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-200'
                          : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-200'
                      }`}>
                        {user.is_disabled ? 'Disabled' : 'Active'}
                      </span>
                      {user.must_reset_password && (
                        <span className="ml-2 px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200">
                          Reset required
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        user.mfa_enabled
                          ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-200'
                          : 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200'
                      }`}>
                        {user.mfa_enabled ? 'Enabled' : 'None'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {user.last_login_at ? new Date(user.last_login_at).toLocaleString() : '-'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {user.created_at ? new Date(user.created_at).toLocaleDateString() : '-'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <button
                        onClick={() => openDetails(user)}
                        className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 mr-3"
                        title="View user details"
                      >
                        <Eye className="w-5 h-5" />
                      </button>
                      <button
                        onClick={() => openEdit(user)}
                        className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-300 mr-3"
                        title="Edit permissions"
                      >
                        <Edit2 className="w-5 h-5" />
                      </button>
                      <button
                        onClick={() => handleRoleToggle(user)}
                        className="text-primary-600 hover:text-primary-900 dark:text-primary-400 dark:hover:text-primary-300 mr-3"
                        title={user.role === 'admin' ? 'Set Full Access' : 'Make Admin'}
                      >
                        {user.role === 'admin' ? <ShieldOff className="w-5 h-5" /> : <Shield className="w-5 h-5" />}
                      </button>
                      <button
                        onClick={() => handleStatusToggle(user)}
                        className="text-amber-600 hover:text-amber-800 dark:text-amber-400 dark:hover:text-amber-300 mr-3"
                        title={user.is_disabled ? 'Enable user' : 'Disable user'}
                      >
                        {user.is_disabled ? <UserCheck className="w-5 h-5" /> : <UserX className="w-5 h-5" />}
                      </button>
                      <button
                        onClick={() => openResetPassword(user)}
                        className="text-indigo-600 hover:text-indigo-800 dark:text-indigo-400 dark:hover:text-indigo-300 mr-3"
                        title="Reset password"
                      >
                        <KeyRound className="w-5 h-5" />
                      </button>
                      <button
                        onClick={() => handleResetMfa(user)}
                        className="text-teal-600 hover:text-teal-800 dark:text-teal-400 dark:hover:text-teal-300 mr-3"
                        title="Reset MFA"
                      >
                        <Lock className="w-5 h-5" />
                      </button>
                      <button
                        onClick={() => handleRevokeSessions(user)}
                        className="text-slate-600 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-300 mr-3"
                        title="Revoke sessions"
                      >
                        <LogOut className="w-5 h-5" />
                      </button>
                      {user.username !== currentUser && (
                        <button
                          onClick={() => initiateDelete(user)}
                          className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                          title="Delete User"
                        >
                          <Trash2 className="w-5 h-5" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="px-6 py-8 text-center text-sm text-gray-500 dark:text-gray-400">
                    No users found matching "{searchTerm}"
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Create User Modal */}
      <Modal isOpen={isCreateModalOpen} onClose={() => setIsCreateModalOpen(false)} title="Create User">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Username</label>
            <input
              type="text"
              className="mt-1 w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm text-gray-900 dark:text-white"
              value={createForm.username}
              onChange={(e) => setCreateForm({ ...createForm, username: e.target.value })}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Temporary Password</label>
            <div className="mt-1 flex gap-2">
              <input
                type="text"
                className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm text-gray-900 dark:text-white font-mono"
                value={createForm.password}
                onChange={(e) => {
                  setCreateForm({ ...createForm, password: e.target.value });
                  setCreatePwCopied(false);
                }}
              />
              <button
                type="button"
                onClick={() => {
                  setCreateForm({ ...createForm, password: generateTempPassword(12) });
                  setCreatePwCopied(false);
                }}
                className="whitespace-nowrap rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-600"
                title="Generate a 12-character password"
              >
                Generate
              </button>
              <button
                type="button"
                onClick={async () => {
                  const ok = await copyToClipboard(createForm.password);
                  setCreatePwCopied(ok);
                }}
                className="whitespace-nowrap rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-600"
                title="Copy password"
                disabled={!createForm.password}
              >
                {createPwCopied ? 'Copied' : 'Copy'}
              </button>
            </div>
            <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
              12 chars with uppercase, lowercase, digit, and symbol (for sharing to the new user).
            </p>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Role</label>
              <select
                className="mt-1 w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm text-gray-900 dark:text-white"
                value={createForm.role}
                onChange={(e) => setCreateForm({ ...createForm, role: e.target.value as 'admin' | 'full-access' | 'modify' | 'view' })}
              >
                <option value="view">View Only</option>
                <option value="modify">Modify</option>
                <option value="full-access">Full Access</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            <div className="flex items-end">
              <label className="inline-flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                <input
                  type="checkbox"
                  checked={createForm.must_reset_password}
                  onChange={(e) => setCreateForm({ ...createForm, must_reset_password: e.target.checked })}
                />
                Require reset on login
              </label>
            </div>
          </div>
          <label className="inline-flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
            <input
              type="checkbox"
              checked={createForm.is_disabled}
              onChange={(e) => setCreateForm({ ...createForm, is_disabled: e.target.checked })}
            />
            Create as disabled
          </label>
          <div className="flex gap-3 pt-2">
            <button
              onClick={() => setIsCreateModalOpen(false)}
              className="flex-1 justify-center rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 shadow-sm hover:bg-gray-50 dark:hover:bg-gray-600"
            >
              Cancel
            </button>
            <button
              onClick={handleCreateUser}
              className="flex-1 justify-center rounded-md border border-transparent bg-primary-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-primary-700"
            >
              Create User
            </button>
          </div>
        </div>
      </Modal>

      {/* Share Credentials Modal */}
      <Modal isOpen={isCredsModalOpen} onClose={() => setIsCredsModalOpen(false)} title="Share Credentials">
        <div className="space-y-4">
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Share these credentials with the new user:
          </p>
          <div className="rounded-md border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 p-3 font-mono text-sm text-gray-900 dark:text-white">
            <div>Username: {createdCreds?.username || '-'}</div>
            <div>Password: {createdCreds?.password || '-'}</div>
          </div>
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={async () => {
                const text = createdCreds ? `Username: ${createdCreds.username}\nPassword: ${createdCreds.password}` : '';
                const ok = await copyToClipboard(text);
                setCredsCopied(ok);
              }}
              className="flex-1 justify-center rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 shadow-sm hover:bg-gray-50 dark:hover:bg-gray-600"
              disabled={!createdCreds}
            >
              {credsCopied ? 'Copied' : 'Copy Both'}
            </button>
            <button
              type="button"
              onClick={() => setIsCredsModalOpen(false)}
              className="flex-1 justify-center rounded-md border border-transparent bg-primary-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-primary-700"
            >
              Done
            </button>
          </div>
        </div>
      </Modal>

      {/* Edit User Modal */}
      <Modal isOpen={isEditModalOpen} onClose={() => setIsEditModalOpen(false)} title="Edit Permissions">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Username</label>
            <input
              type="text"
              className="mt-1 w-full rounded-md border border-gray-300 dark:border-gray-600 bg-gray-100 dark:bg-gray-800 px-3 py-2 text-sm text-gray-900 dark:text-white"
              value={editUser?.username || ''}
              disabled
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Role</label>
            <select
              className="mt-1 w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm text-gray-900 dark:text-white"
              value={editForm.role}
              onChange={(e) => setEditForm({ ...editForm, role: e.target.value as 'admin' | 'full-access' | 'modify' | 'view' })}
            >
              <option value="view">View Only</option>
              <option value="modify">Modify</option>
              <option value="full-access">Full Access</option>
              <option value="admin">Admin</option>
            </select>
            <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
              View: read-only. Modify: add/edit only. Full Access: add/edit/delete (no admin panel). Admin: full access + user management + audit logs.
            </p>
          </div>
          <div className="space-y-3">
            <label className="inline-flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
              <input
                type="checkbox"
                checked={editForm.is_disabled}
                onChange={(e) => setEditForm({ ...editForm, is_disabled: e.target.checked })}
              />
              Disable user
            </label>
            <label className="inline-flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
              <input
                type="checkbox"
                checked={editForm.must_reset_password}
                onChange={(e) => setEditForm({ ...editForm, must_reset_password: e.target.checked })}
              />
              Require password reset on next login
            </label>
          </div>
          <div className="flex gap-3 pt-2">
            <button
              onClick={() => setIsEditModalOpen(false)}
              className="flex-1 justify-center rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 shadow-sm hover:bg-gray-50 dark:hover:bg-gray-600"
            >
              Cancel
            </button>
            <button
              onClick={handleEditUser}
              className="flex-1 justify-center rounded-md border border-transparent bg-green-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-green-700"
            >
              Update User
            </button>
          </div>
        </div>
      </Modal>

      {/* Reset Password Modal */}
      <Modal isOpen={isResetModalOpen} onClose={() => setIsResetModalOpen(false)} title="Reset Password">
        <div className="space-y-4">
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Set a temporary password for <strong>{resetUser?.username}</strong>.
          </p>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Temporary Password</label>
            <input
              type="text"
              className="mt-1 w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm text-gray-900 dark:text-white"
              value={resetPassword}
              onChange={(e) => setResetPassword(e.target.value)}
            />
          </div>
          <div className="flex gap-3 pt-2">
            <button
              onClick={() => setIsResetModalOpen(false)}
              className="flex-1 justify-center rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 shadow-sm hover:bg-gray-50 dark:hover:bg-gray-600"
            >
              Cancel
            </button>
            <button
              onClick={handleResetPassword}
              className="flex-1 justify-center rounded-md border border-transparent bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700"
              disabled={!resetPassword}
            >
              Set Password
            </button>
          </div>
        </div>
      </Modal>

      {/* User Details Modal */}
      <Modal isOpen={isDetailsOpen} onClose={() => setIsDetailsOpen(false)} title="User Details">
        {detailsLoading ? (
          <div className="flex justify-center py-6">
            <Loader2 className="w-6 h-6 animate-spin text-primary-600" />
          </div>
        ) : detailsUser ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <p className="text-gray-500 dark:text-gray-400">Username</p>
                <p className="font-medium text-gray-900 dark:text-white">{detailsUser.username}</p>
              </div>
              <div>
                <p className="text-gray-500 dark:text-gray-400">Role</p>
                <p className="font-medium text-gray-900 dark:text-white">{getRoleDisplay(detailsUser.role)}</p>
              </div>
              <div>
                <p className="text-gray-500 dark:text-gray-400">Status</p>
                <p className="font-medium text-gray-900 dark:text-white">{detailsUser.is_disabled ? 'Disabled' : 'Active'}</p>
              </div>
              <div>
                <p className="text-gray-500 dark:text-gray-400">MFA</p>
                <p className="font-medium text-gray-900 dark:text-white">{detailsUser.mfa_enabled ? 'Enabled' : 'None'}</p>
              </div>
              <div>
                <p className="text-gray-500 dark:text-gray-400">Reset Required</p>
                <p className="font-medium text-gray-900 dark:text-white">{detailsUser.must_reset_password ? 'Yes' : 'No'}</p>
              </div>
              <div>
                <p className="text-gray-500 dark:text-gray-400">Last Login</p>
                <p className="font-medium text-gray-900 dark:text-white">{detailsUser.last_login_at ? new Date(detailsUser.last_login_at).toLocaleString() : '-'}</p>
              </div>
              <div>
                <p className="text-gray-500 dark:text-gray-400">Password Changed</p>
                <p className="font-medium text-gray-900 dark:text-white">{detailsUser.password_changed_at ? new Date(detailsUser.password_changed_at).toLocaleString() : '-'}</p>
              </div>
            </div>

            <div>
              <h4 className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                <Users className="w-4 h-4" />
                Recent Activity
              </h4>
              <div className="mt-2 max-h-60 overflow-y-auto border border-gray-200 dark:border-gray-700 rounded-md bg-white dark:bg-gray-800">
                {detailsLogs.length === 0 ? (
                  <div className="p-4 text-sm text-gray-500 dark:text-gray-400">No audit logs found.</div>
                ) : (
                  detailsLogs.map((log) => (
                    <div key={log.id} className="px-4 py-2 border-b border-gray-100 dark:border-gray-700 text-xs">
                      <div className="flex justify-between text-gray-600 dark:text-gray-300">
                        <span className="font-mono">{log.action}</span>
                        <span>{new Date(log.timestamp).toLocaleString()}</span>
                      </div>
                      <div className="text-gray-500 dark:text-gray-400">{log.details}</div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="text-sm text-gray-500 dark:text-gray-400">No user selected.</div>
        )}
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={isDeleteModalOpen}
        onClose={() => setIsDeleteModalOpen(false)}
        title="Delete User"
      >
        <div className="flex flex-col items-center text-center">
          <div className="bg-red-100 dark:bg-red-900/30 p-3 rounded-full mb-4">
            <AlertTriangle className="w-8 h-8 text-red-600 dark:text-red-400" />
          </div>
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Are you sure?</h3>
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
            This will permanently delete user <strong>{userToDelete?.username}</strong>. This action cannot be undone.
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
              Delete User
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};

export default AdminUsers;
