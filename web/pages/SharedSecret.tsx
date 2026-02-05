import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import * as secretService from '../services/secretService';
import { Secret } from '../types';
import { Shield, Eye, EyeOff, Copy, AlertTriangle, Loader2, Globe, FileText, Database, Key, Lock } from 'lucide-react';

const SharedSecret: React.FC = () => {
  const { token } = useParams<{ token: string }>();
  const [secret, setSecret] = useState<Secret | null>(null);
  const [loading, setLoading] = useState(false); // Do not load automatically to prevent view count consumption
  const [error, setError] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [revealed, setRevealed] = useState(false);

  const handleReveal = async () => {
      if (!token) return;
      setLoading(true);
      try {
          const data = await secretService.getSharedSecret(token);
          setSecret(data);
          setRevealed(true);
      } catch (err: any) {
          setError(err.message || 'Failed to load secret');
      } finally {
          setLoading(false);
      }
  };

  const copyToClipboard = (text?: string) => {
    if (text) {
      navigator.clipboard.writeText(text);
      alert('Copied to clipboard!');
    }
  };

  if (error) {
      return (
          <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex flex-col justify-center py-12 sm:px-6 lg:px-8 px-4">
              <div className="sm:mx-auto sm:w-full sm:max-w-md text-center">
                  <div className="mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-red-100 dark:bg-red-900/30 mb-6">
                      <AlertTriangle className="h-8 w-8 text-red-600 dark:text-red-400" />
                  </div>
                  <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">Access Denied</h2>
                  <p className="text-gray-500 dark:text-gray-400 mb-6">{error}</p>
                  <Link to="/" className="text-primary-600 hover:text-primary-500 font-medium">Return to Home</Link>
              </div>
          </div>
      );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex flex-col justify-center py-12 sm:px-6 lg:px-8 transition-colors duration-200">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center">
            <div className="rounded-full bg-primary-600 p-3">
                <Shield className="h-10 w-10 text-white" />
            </div>
        </div>
        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-white">Secure Secret Share</h2>
        <p className="mt-2 text-center text-sm text-gray-600 dark:text-gray-400">
             You have received a secure, temporary link.
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white dark:bg-gray-800 py-8 px-4 shadow sm:rounded-lg sm:px-10 border border-gray-100 dark:border-gray-700">
             
             {!revealed ? (
                 <div className="text-center">
                     <p className="text-gray-700 dark:text-gray-300 mb-6">
                         Click the button below to reveal the secret. 
                         <br/>
                         <span className="text-xs text-gray-500 dark:text-gray-400 block mt-2">
                             Note: This may count towards a view limit and the link might expire afterwards.
                         </span>
                     </p>
                     <button
                        onClick={handleReveal}
                        disabled={loading}
                        className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                     >
                        {loading ? <Loader2 className="animate-spin h-5 w-5" /> : 'Reveal Secret'}
                     </button>
                 </div>
             ) : (
                 <div className="space-y-6">
                    {secret && (
                        <>
                            <div className="flex items-center gap-2 pb-4 border-b border-gray-100 dark:border-gray-700">
                                <h3 className="text-xl font-bold text-gray-900 dark:text-white">{secret.title}</h3>
                            </div>

                            {secret.username && (
                                <div className="bg-gray-50 dark:bg-gray-700 p-3 rounded-md">
                                    <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase">Username</label>
                                    <div className="flex justify-between items-center mt-1">
                                        <span className="font-mono text-gray-900 dark:text-gray-100">{secret.username}</span>
                                        <button onClick={() => copyToClipboard(secret.username)} className="text-gray-400 hover:text-primary-600 dark:hover:text-primary-400"><Copy className="w-4 h-4"/></button>
                                    </div>
                                </div>
                            )}

                            {secret.password && (
                                <div className="bg-gray-50 dark:bg-gray-700 p-3 rounded-md">
                                    <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase">Password</label>
                                    <div className="flex justify-between items-center mt-1">
                                        <span className="font-mono text-gray-900 dark:text-gray-100 break-all">{showPassword ? secret.password : '••••••••••••'}</span>
                                        <div className="flex gap-2">
                                            <button onClick={() => setShowPassword(!showPassword)} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
                                                {showPassword ? <EyeOff className="w-4 h-4"/> : <Eye className="w-4 h-4"/>}
                                            </button>
                                            <button onClick={() => copyToClipboard(secret.password)} className="text-gray-400 hover:text-primary-600 dark:hover:text-primary-400"><Copy className="w-4 h-4"/></button>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {secret.api_key && (
                                <div className="bg-gray-50 dark:bg-gray-700 p-3 rounded-md">
                                    <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase">API Key</label>
                                    <div className="flex justify-between items-center mt-1">
                                        <span className="font-mono text-gray-900 dark:text-gray-100 break-all">{showPassword ? secret.api_key : '••••••••••••'}</span>
                                        <div className="flex gap-2">
                                            <button onClick={() => setShowPassword(!showPassword)} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
                                                {showPassword ? <EyeOff className="w-4 h-4"/> : <Eye className="w-4 h-4"/>}
                                            </button>
                                            <button onClick={() => copyToClipboard(secret.api_key)} className="text-gray-400 hover:text-primary-600 dark:hover:text-primary-400"><Copy className="w-4 h-4"/></button>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {secret.url && (
                                <div className="p-1">
                                    <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase">Notes</label>
                                     <div className="mt-1">
                                        <a href={secret.url} target="_blank" rel="noreferrer" className="text-primary-600 dark:text-primary-400 hover:underline flex items-center gap-1 break-all">
                                            <Globe className="w-3 h-3"/> {secret.url}
                                        </a>
                                     </div>
                                </div>
                            )}

                            {secret.notes && (
                                <div className="p-1">
                                    <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase">Notes</label>
                                    <div className="mt-1 text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap bg-yellow-50 dark:bg-yellow-900/20 p-2 rounded border border-yellow-100 dark:border-yellow-900/30">
                                        {secret.notes}
                                    </div>
                                </div>
                            )}
                        </>
                    )}
                 </div>
             )}
        </div>
      </div>
    </div>
  );
};

export default SharedSecret;