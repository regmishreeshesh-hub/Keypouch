import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
    Users,
    Shield,
    Activity,
    UserPlus,
    ArrowRight,
    Loader2,
    Clock,
    Database,
    Lock
} from 'lucide-react';
import * as authService from '../services/authService';
import * as auditService from '../services/auditService';
import { AuditLog } from '../types';

const AdminDashboard: React.FC = () => {
    const [userCount, setUserCount] = useState<number | null>(null);
    const [recentLogs, setRecentLogs] = useState<AuditLog[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        const fetchDashboardData = async () => {
            setLoading(true);
            try {
                const [users, logs] = await Promise.all([
                    authService.getUsers(),
                    auditService.getAuditLogs()
                ]);
                setUserCount(users.length);
                setRecentLogs(logs.slice(0, 5));
                setError('');
            } catch (err: any) {
                setError(err.message || 'Failed to fetch dashboard data');
            } finally {
                setLoading(false);
            }
        };

        fetchDashboardData();
    }, []);

    if (loading) {
        return (
            <div className="flex items-center justify-center min-h-[400px]">
                <Loader2 className="w-8 h-8 animate-spin text-primary-600" />
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Admin Dashboard</h1>
                    <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">System overview and management.</p>
                </div>
            </div>

            {error && (
                <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-md text-red-700 dark:text-red-300">
                    {error}
                </div>
            )}

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-white dark:bg-gray-800 p-6 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm transition-all hover:shadow-md">
                    <div className="flex items-center gap-4">
                        <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
                            <Users className="w-6 h-6 text-blue-600 dark:text-blue-400" />
                        </div>
                        <div>
                            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Total Users</p>
                            <h3 className="text-2xl font-bold text-gray-900 dark:text-white">{userCount ?? '...'}</h3>
                        </div>
                    </div>
                    <Link to="/admin/users" className="mt-4 flex items-center text-sm font-medium text-blue-600 dark:text-blue-400 hover:underline">
                        Manage Users <ArrowRight className="w-4 h-4 ml-1" />
                    </Link>
                </div>

                <div className="bg-white dark:bg-gray-800 p-6 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm transition-all hover:shadow-md">
                    <div className="flex items-center gap-4">
                        <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
                            <Shield className="w-6 h-6 text-purple-600 dark:text-purple-400" />
                        </div>
                        <div>
                            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Audit Logs</p>
                            <h3 className="text-2xl font-bold text-gray-900 dark:text-white">Active</h3>
                        </div>
                    </div>
                    <Link to="/admin/logs" className="mt-4 flex items-center text-sm font-medium text-purple-600 dark:text-purple-400 hover:underline">
                        View Activity <ArrowRight className="w-4 h-4 ml-1" />
                    </Link>
                </div>

                <div className="bg-white dark:bg-gray-800 p-6 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm transition-all hover:shadow-md">
                    <div className="flex items-center gap-4">
                        <div className="p-3 bg-green-100 dark:bg-green-900/30 rounded-lg">
                            <Database className="w-6 h-6 text-green-600 dark:text-green-400" />
                        </div>
                        <div>
                            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">System Status</p>
                            <h3 className="text-2xl font-bold text-gray-900 dark:text-white">Healthy</h3>
                        </div>
                    </div>
                    <div className="mt-4 flex items-center text-sm font-medium text-green-600 dark:text-green-400">
                        <span className="w-2 h-2 bg-green-500 rounded-full mr-2 animate-pulse"></span>
                        All services operational
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Quick Actions */}
                <div className="bg-white dark:bg-gray-800 p-6 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Quick Actions</h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <Link to="/admin/users" className="flex items-center gap-3 p-3 rounded-lg border border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                            <UserPlus className="w-5 h-5 text-gray-500" />
                            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Add New User</span>
                        </Link>
                        <Link to="/admin/logs" className="flex items-center gap-3 p-3 rounded-lg border border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                            <Activity className="w-5 h-5 text-gray-500" />
                            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Review Logs</span>
                        </Link>
                        <Link to="/secrets" className="flex items-center gap-3 p-3 rounded-lg border border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors sm:col-span-2">
                            <Lock className="w-5 h-5 text-gray-500" />
                            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Access Secure Vault</span>
                        </Link>
                    </div>
                </div>

                {/* Recent Activity */}
                <div className="bg-white dark:bg-gray-800 p-6 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm">
                    <div className="flex items-center justify-between mb-4">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Activity</h3>
                        <Link to="/admin/logs" className="text-xs font-medium text-primary-600 dark:text-primary-400 hover:underline">
                            View All
                        </Link>
                    </div>
                    <div className="space-y-4">
                        {recentLogs.length > 0 ? (
                            recentLogs.map((log) => (
                                <div key={log.id} className="flex gap-3 pb-3 border-b border-gray-100 dark:border-gray-700 last:border-0 last:pb-0">
                                    <div className="flex-shrink-0 mt-1">
                                        <Clock className="w-4 h-4 text-gray-400" />
                                    </div>
                                    <div>
                                        <p className="text-sm text-gray-900 dark:text-white">
                                            <span className="font-semibold">{log.username}</span> {log.action.toLowerCase().replace(/_/g, ' ')}
                                        </p>
                                        <p className="text-xs text-gray-500 dark:text-gray-400">
                                            {new Date(log.timestamp).toLocaleString()}
                                        </p>
                                    </div>
                                </div>
                            ))
                        ) : (
                            <p className="text-sm text-gray-500 py-4 text-center">No recent activity</p>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default AdminDashboard;
