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
      console.log('Starting demo setup...');
      
      // Try multiple possible API endpoints
      const endpoints = [
        '/api/demo/setup',
        'http://localhost:5001/api/demo/setup',
        `${window.location.protocol}//${window.location.hostname}:5001/api/demo/setup`
      ];
      
      let res, responseText, data;
      
      for (const endpoint of endpoints) {
        try {
          console.log('Trying endpoint:', endpoint);
          
          res = await fetch(endpoint, { 
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            }
          });
          
          console.log('Response status:', res.status, res.statusText);
          console.log('Response headers:', Object.fromEntries(res.headers.entries()));
          
          // Get response text first
          responseText = await res.text();
          console.log('Response text:', responseText);
          console.log('Response text length:', responseText.length);
          
          // Check if response is ok
          if (!res.ok) {
            console.error('Response not ok:', res.status);
            throw new Error(responseText || 'Failed to create demo admin');
          }
          
          // Parse JSON
          try {
            data = JSON.parse(responseText);
            console.log('Parsed data:', data);
            break; // Success, exit loop
          } catch (jsonError) {
            console.error('JSON parse error:', jsonError);
            console.error('Response that failed to parse:', responseText);
            throw new Error('Invalid response from server');
          }
          
        } catch (err) {
          console.log('Endpoint failed:', endpoint, err);
          if (endpoint === endpoints[endpoints.length - 1]) {
            // Last endpoint failed, throw the error
            throw err;
          }
          // Try next endpoint
          continue;
        }
      }
      
      // Handle success cases
      if (data.message === 'Demo admin already exists') {
        setSuccess('Demo admin already exists! Redirecting to demo login...');
      } else if (data.message === 'Demo admin created successfully') {
        setSuccess('Demo admin user created! Redirecting to demo login...');
      } else {
        setSuccess('Demo setup complete! Redirecting to demo login...');
      }
      
      setTimeout(() => navigate('/login'), 2000);
    } catch (err: any) {
      console.error('Demo setup error:', err);
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
