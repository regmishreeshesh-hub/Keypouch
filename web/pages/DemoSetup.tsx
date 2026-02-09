import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const DemoSetup: React.FC = () => {
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();

  const handleCreateDemo = async () => {
    setCreating(true);
    setError('');
    setSuccess('');
    try {
      // Call backend to create demo admin user
      const res = await fetch('/api/demo/setup', { method: 'POST' });
      if (!res.ok) throw new Error('Failed to create demo admin');
      setSuccess('Demo admin user created! Redirecting to demo login...');
      setTimeout(() => navigate('/login'), 2000);
    } catch (err: any) {
      setError(err.message || 'Demo setup failed');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gray-50 dark:bg-gray-900 px-4">
      <div className="bg-white dark:bg-gray-800 p-8 rounded shadow-md w-full max-w-md text-center">
        <h2 className="text-2xl font-bold mb-4 text-gray-900 dark:text-white">Demo Mode Setup</h2>
        <div className="text-red-600 dark:text-red-400 mb-4 font-semibold">
          Demo accounts are for local testing only. They cannot access enterprise features or production data.
        </div>
        <button
          className="w-full bg-primary-600 hover:bg-primary-700 text-white font-bold py-2 px-4 rounded mb-4"
          onClick={handleCreateDemo}
          disabled={creating}
        >
          {creating ? 'Creating Demo Admin...' : 'Create Demo Admin User'}
        </button>
        {error && <div className="text-red-600 dark:text-red-400 mb-2">{error}</div>}
        {success && <div className="text-green-600 dark:text-green-400 mb-2">{success}</div>}
        <div className="text-xs text-gray-500 mt-4">
          You can create additional demo users from the demo login page after setup.
        </div>
      </div>
    </div>
  );
};

export default DemoSetup;
