import React from 'react';
import { useNavigate } from 'react-router-dom';

const Welcome: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gray-50 dark:bg-gray-900 px-4">
      <div className="bg-white dark:bg-gray-800 p-8 rounded shadow-md w-full max-w-md text-center">
        <h1 className="text-3xl font-bold mb-4 text-gray-900 dark:text-white">Welcome to KeyPouch</h1>
        <p className="mb-6 text-gray-700 dark:text-gray-300">
          Please select your setup mode. <br />
          <span className="text-xs text-gray-500">(You cannot change this after setup.)</span>
        </p>
        <button
          className="w-full bg-primary-600 hover:bg-primary-700 text-white font-bold py-2 px-4 rounded mb-4"
          onClick={() => navigate('/admin-setup')}
        >
          Admin Setup (Recommended)
        </button>
        <div className="text-xs text-gray-500 mb-2">For production, secure, multi-user deployments</div>
        <button
          className="w-full bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold py-2 px-4 rounded"
          onClick={() => navigate('/demo-setup')}
        >
          Demo Mode
        </button>
        <div className="text-xs text-gray-500 mt-2">For local, personal, or evaluation use only</div>
      </div>
    </div>
  );
};

export default Welcome;
