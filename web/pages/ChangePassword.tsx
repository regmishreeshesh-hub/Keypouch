import React, { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import * as authService from '../services/authService';
import { Shield, Loader2, Check, X } from 'lucide-react';

const ChangePassword: React.FC = () => {
  const navigate = useNavigate();
  const forced = localStorage.getItem('must_reset_password') === 'true';

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const passValidation = useMemo(() => {
    return {
      length: newPassword.length >= 8,
      number: /[0-9]/.test(newPassword),
      letter: /[a-zA-Z]/.test(newPassword),
    };
  }, [newPassword]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!forced && !currentPassword) {
      setError('Current password is required');
      return;
    }

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (!passValidation.length || !passValidation.number || !passValidation.letter) {
      setError('Password does not meet requirements');
      return;
    }

    setLoading(true);
    try {
      const response = await authService.changeMyPassword({
        current_password: forced ? undefined : currentPassword,
        new_password: newPassword,
      });
      localStorage.setItem('token', response.token);
      localStorage.setItem('must_reset_password', 'false');
      navigate('/contacts', { replace: true });
    } catch (err: any) {
      setError(err.message || 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-xl mx-auto">
      <div className="bg-white dark:bg-gray-800 border border-gray-100 dark:border-gray-700 rounded-lg shadow p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="rounded-full bg-primary-600 p-2">
            <Shield className="h-5 w-5 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-gray-900 dark:text-white">Change Password</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {forced ? 'You must change your password before continuing.' : 'Update your password.'}
            </p>
          </div>
        </div>

        <form className="space-y-4" onSubmit={handleSubmit}>
          {!forced && (
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Current Password</label>
              <input
                type="password"
                className="mt-1 w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm text-gray-900 dark:text-white"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
              />
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">New Password</label>
            <input
              type="password"
              className="mt-1 w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm text-gray-900 dark:text-white"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
            <div className="mt-2 grid grid-cols-1 gap-1 text-xs text-gray-500 dark:text-gray-400">
              <div className={`flex items-center gap-1 ${passValidation.length ? 'text-green-600 dark:text-green-400' : ''}`}>
                {passValidation.length ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />} At least 8 characters
              </div>
              <div className={`flex items-center gap-1 ${passValidation.letter ? 'text-green-600 dark:text-green-400' : ''}`}>
                {passValidation.letter ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />} At least one letter
              </div>
              <div className={`flex items-center gap-1 ${passValidation.number ? 'text-green-600 dark:text-green-400' : ''}`}>
                {passValidation.number ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />} At least one number
              </div>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Confirm New Password</label>
            <input
              type="password"
              className="mt-1 w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm text-gray-900 dark:text-white"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
          </div>

          {error && (
            <div className="rounded-md bg-red-50 dark:bg-red-900/20 p-4">
              <div className="text-sm font-medium text-red-800 dark:text-red-300">{error}</div>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full flex justify-center items-center gap-2 rounded-md bg-primary-600 px-4 py-2 text-sm font-semibold text-white hover:bg-primary-700 disabled:opacity-50"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
            Save New Password
          </button>
        </form>
      </div>
    </div>
  );
};

export default ChangePassword;
