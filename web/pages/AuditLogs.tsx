import React, { useEffect, useState } from 'react';
import { AuditLog } from '../types';
import * as auditService from '../services/auditService';
import { 
  Search, Loader2, ShieldAlert, Activity, Filter, RefreshCw, 
  Eye, Share2, Key, Shield, User, LogIn, Plus, Trash2, Edit2, Globe
} from 'lucide-react';

const AuditLogs: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState<'ALL' | 'SECRET' | 'USER' | 'SYSTEM'>('ALL');

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const data = await auditService.getAuditLogs();
      setLogs(data);
      setError('');
    } catch (err: any) {
      setError(err.message || 'Failed to fetch logs. You might not have permission.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const filteredLogs = logs.filter(log => {
      const matchesSearch = log.username.toLowerCase().includes(searchTerm.toLowerCase()) || 
                            log.details.toLowerCase().includes(searchTerm.toLowerCase()) ||
                            log.ip.includes(searchTerm);
      const matchesAction = actionFilter ? log.action === actionFilter : true;
      
      let matchesType = true;
      if (typeFilter === 'SECRET') {
          matchesType = log.action.startsWith('SECRET') || log.action === 'SHARED_VIEW';
      } else if (typeFilter === 'USER') {
          matchesType = log.action.startsWith('USER') || log.action.startsWith('LOGIN') || log.action === 'REGISTER' || log.action.startsWith('SECURITY');
      } else if (typeFilter === 'SYSTEM') {
          matchesType = log.action === 'SYSTEM_INIT';
      }

      return matchesSearch && matchesAction && matchesType;
  });

  const uniqueActions = Array.from(new Set(logs.map(log => log.action))).sort();

  const getActionConfig = (action: string) => {
      // Secret Related
      if (action === 'SECRET_VIEW') return { color: 'text-indigo-600 bg-indigo-100 dark:bg-indigo-900/30 dark:text-indigo-400', icon: Eye, label: 'Viewed Secret' };
      if (action === 'SECRET_SHARE') return { color: 'text-pink-600 bg-pink-100 dark:bg-pink-900/30 dark:text-pink-400', icon: Share2, label: 'Shared Secret' };
      if (action === 'SHARED_VIEW') return { color: 'text-amber-600 bg-amber-100 dark:bg-amber-900/30 dark:text-amber-400', icon: Globe, label: 'Public Access' };
      if (action === 'SECRET_CREATE') return { color: 'text-indigo-600 bg-indigo-100 dark:bg-indigo-900/30 dark:text-indigo-400', icon: Plus, label: 'Created Secret' };
      if (action === 'SECRET_UPDATE') return { color: 'text-indigo-600 bg-indigo-100 dark:bg-indigo-900/30 dark:text-indigo-400', icon: Edit2, label: 'Edited Secret' };
      if (action === 'SECRET_DELETE') return { color: 'text-red-600 bg-red-100 dark:bg-red-900/30 dark:text-red-400', icon: Trash2, label: 'Deleted Secret' };

      // User Related
      if (action === 'LOGIN') return { color: 'text-green-600 bg-green-100 dark:bg-green-900/30 dark:text-green-400', icon: LogIn, label: 'Login' };
      if (action === 'LOGIN_FAILED') return { color: 'text-orange-600 bg-orange-100 dark:bg-orange-900/30 dark:text-orange-400', icon: ShieldAlert, label: 'Login Failed' };
      if (action === 'USER_CREATE') return { color: 'text-blue-600 bg-blue-100 dark:bg-blue-900/30 dark:text-blue-400', icon: User, label: 'User Created' };
      if (action === 'USER_UPDATE') return { color: 'text-blue-600 bg-blue-100 dark:bg-blue-900/30 dark:text-blue-400', icon: User, label: 'User Updated' };
      if (action === 'USER_DELETE') return { color: 'text-red-600 bg-red-100 dark:bg-red-900/30 dark:text-red-400', icon: User, label: 'User Deleted' };
      if (action === 'REGISTER') return { color: 'text-green-600 bg-green-100 dark:bg-green-900/30 dark:text-green-400', icon: Plus, label: 'Registered' };

      // Default
      return { color: 'text-gray-600 bg-gray-100 dark:bg-gray-700 dark:text-gray-300', icon: Activity, label: action };
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
              <Shield className="w-6 h-6 text-primary-600" />
              Security Audit Logs
          </h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              Track sensitive access and system changes.
          </p>
        </div>
        <button onClick={fetchLogs} className="p-2 text-gray-500 hover:text-primary-600 dark:text-gray-400 dark:hover:text-primary-300 transition-colors">
            <RefreshCw className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      <div className="flex flex-col md:flex-row gap-4">
        {/* Search */}
        <div className="relative flex-1">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <Search className="h-5 w-5 text-gray-400" />
          </div>
          <input
            type="text"
            className="block w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg leading-5 bg-white dark:bg-gray-800 placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-primary-500 focus:border-primary-500 sm:text-sm shadow-sm text-gray-900 dark:text-white"
            placeholder="Search by user, details, or IP..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        {/* Type Filter */}
        <div className="w-full md:w-48">
            <select
                className="block w-full pl-3 pr-10 py-2 text-base border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm rounded-lg"
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value as any)}
            >
                <option value="ALL">All Categories</option>
                <option value="SECRET">Secret Activity</option>
                <option value="USER">User Activity</option>
                <option value="SYSTEM">System Activity</option>
            </select>
        </div>

        {/* Action Filter */}
        <div className="relative w-full md:w-56">
             <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Filter className="h-4 w-4 text-gray-400" />
             </div>
            <select
            className="block w-full pl-10 pr-10 py-2 text-base border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm rounded-lg"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            >
            <option value="">All Actions</option>
            {uniqueActions.map(action => (
                <option key={action} value={action}>{action}</option>
            ))}
            </select>
        </div>
      </div>

      {loading && logs.length === 0 ? (
        <div className="flex justify-center py-12">
          <Loader2 className="w-8 h-8 animate-spin text-primary-600" />
        </div>
      ) : error ? (
        <div className="bg-red-50 dark:bg-red-900/20 p-6 rounded-lg text-center">
            <ShieldAlert className="w-12 h-12 text-red-500 mx-auto mb-3" />
            <h3 className="text-lg font-medium text-red-800 dark:text-red-300">Access Denied</h3>
            <p className="mt-2 text-red-600 dark:text-red-400">{error}</p>
        </div>
      ) : (
        <div className="bg-white dark:bg-gray-800 shadow overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead className="bg-gray-50 dark:bg-gray-900">
                  <tr>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Timestamp
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      User
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Action
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Details
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      IP / Source
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                  {filteredLogs.length > 0 ? (
                    filteredLogs.map((log) => {
                      const config = getActionConfig(log.action);
                      const Icon = config.icon;
                      
                      return (
                        <tr key={log.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                                {new Date(log.timestamp).toLocaleString()}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                                <div className="flex items-center">
                                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                                        {log.username === 'anonymous' ? <span className="italic text-gray-500">Anonymous</span> : log.username}
                                    </div>
                                </div>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                                <span className={`px-2 py-1 inline-flex items-center gap-1.5 text-xs leading-5 font-semibold rounded-full ${config.color}`}>
                                    <Icon className="w-3 h-3" />
                                    {config.label}
                                </span>
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-300">
                                {log.details}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400 font-mono">
                                {log.ip}
                            </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={5} className="px-6 py-12 text-center text-sm text-gray-500 dark:text-gray-400">
                          <div className="flex flex-col items-center justify-center">
                              <Shield className="w-12 h-12 text-gray-300 mb-2" />
                              <p>No audit logs found matching your criteria.</p>
                          </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default AuditLogs;