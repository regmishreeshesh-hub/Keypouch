import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import * as authService from '../services/authService';
import { Shield, Loader2, Check, X, Sun, Moon } from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';

const ResetPassword: React.FC = () => {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { theme, toggleTheme } = useTheme();

  useEffect(() => {
      if (!token) {
          setError('Invalid or missing reset token.');
      }
  }, [token]);

  const validatePassword = (pass: string) => {
      return {
          length: pass.length >= 8,
          number: /[0-9]/.test(pass),
          letter: /[a-zA-Z]/.test(pass)
      }
  }

  const getPasswordStrength = (pass: string) => {
    let score = 0;
    if (pass.length === 0) return 0;
    if (pass.length >= 8) score += 1;
    if (pass.length >= 12) score += 1;
    if (/[0-9]/.test(pass)) score += 1;
    if (/[a-z]/.test(pass) && /[A-Z]/.test(pass)) score += 1;
    if (/[^A-Za-z0-9]/.test(pass)) score += 1;
    return score;
  };

  const strength = getPasswordStrength(password);
  const getStrengthConfig = (s: number) => {
      if (s === 0) return { label: '', color: 'bg-gray-200 dark:bg-gray-700', width: '0%' };
      if (s <= 1) return { label: 'Very Weak', color: 'bg-red-500', width: '20%' };
      if (s <= 2) return { label: 'Weak', color: 'bg-orange-500', width: '40%' };
      if (s <= 3) return { label: 'Fair', color: 'bg-yellow-500', width: '60%' };
      if (s <= 4) return { label: 'Good', color: 'bg-blue-500', width: '80%' };
      return { label: 'Strong', color: 'bg-green-500', width: '100%' };
  };

  const strengthConfig = getStrengthConfig(strength);
  const passValidation = validatePassword(password);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!token) {
        setError('Missing token');
        return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (!passValidation.length || !passValidation.number || !passValidation.letter) {
        setError('Password does not meet requirements');
        return;
    }

    setLoading(true);
    
    try {
      await authService.resetPassword(token, password);
      navigate('/login', { state: { success: 'Password has been reset successfully. Please login with your new password.' } });
    } catch (err: any) {
      setError(err.message || 'Failed to reset password');
    } finally {
      setLoading(false);
    }
  };

  if (!token) {
       return (
        <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
            <div className="sm:mx-auto sm:w-full sm:max-w-md bg-white dark:bg-gray-800 p-8 rounded-lg shadow text-center">
                 <X className="mx-auto h-12 w-12 text-red-500" />
                 <h3 className="mt-2 text-lg font-medium text-gray-900 dark:text-white">Invalid Request</h3>
                 <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">Missing password reset token.</p>
                 <button onClick={() => navigate('/login')} className="mt-4 text-primary-600 hover:text-primary-500">Back to Login</button>
            </div>
        </div>
       )
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex flex-col justify-center py-12 sm:px-6 lg:px-8 transition-colors duration-200">
      
      <div className="absolute top-4 right-4">
        <button
          onClick={toggleTheme}
          className="p-2 rounded-full text-gray-500 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
        >
          {theme === 'light' ? <Moon className="w-5 h-5" /> : <Sun className="w-5 h-5" />}
        </button>
      </div>

      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center">
             <div className="rounded-full bg-primary-600 p-3">
                <Shield className="h-10 w-10 text-white" />
            </div>
        </div>
        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-white">Set New Password</h2>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white dark:bg-gray-800 py-8 px-4 shadow sm:rounded-lg sm:px-10 border border-gray-100 dark:border-gray-700">
          <form className="space-y-6" onSubmit={handleSubmit}>
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                New Password
              </label>
              <div className="mt-1">
                <input
                  id="password"
                  name="password"
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="appearance-none block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                />
              </div>
              
               {/* Password Strength Meter */}
               {password.length > 0 && (
                   <div className="mt-2">
                       <div className="flex justify-between items-center mb-1">
                           <span className="text-xs text-gray-500 dark:text-gray-400 font-medium">Strength</span>
                           <span className="text-xs text-gray-700 dark:text-gray-300 font-semibold">{strengthConfig.label}</span>
                       </div>
                       <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5 transition-all duration-300">
                           <div 
                               className={`h-1.5 rounded-full transition-all duration-500 ease-out ${strengthConfig.color}`} 
                               style={{ width: strengthConfig.width }}
                           ></div>
                       </div>
                   </div>
               )}

               <div className="mt-3 grid grid-cols-1 gap-1 text-xs text-gray-500 dark:text-gray-400">
                  <div className={`flex items-center gap-1 ${passValidation.length ? 'text-green-600 dark:text-green-400' : ''}`}>
                      {passValidation.length ? <Check className="w-3 h-3"/> : <X className="w-3 h-3"/>} At least 8 characters
                  </div>
                  <div className={`flex items-center gap-1 ${passValidation.letter ? 'text-green-600 dark:text-green-400' : ''}`}>
                      {passValidation.letter ? <Check className="w-3 h-3"/> : <X className="w-3 h-3"/>} At least one letter
                  </div>
                  <div className={`flex items-center gap-1 ${passValidation.number ? 'text-green-600 dark:text-green-400' : ''}`}>
                      {passValidation.number ? <Check className="w-3 h-3"/> : <X className="w-3 h-3"/>} At least one number
                  </div>
              </div>
            </div>

            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Confirm New Password
              </label>
              <div className="mt-1">
                <input
                  id="confirmPassword"
                  name="confirmPassword"
                  type="password"
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="appearance-none block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                />
              </div>
            </div>

            {error && (
              <div className="rounded-md bg-red-50 dark:bg-red-900/20 p-4">
                <div className="flex">
                  <div className="ml-3">
                    <h3 className="text-sm font-medium text-red-800 dark:text-red-300">{error}</h3>
                  </div>
                </div>
              </div>
            )}

            <div>
              <button
                type="submit"
                disabled={loading}
                className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? <Loader2 className="animate-spin h-5 w-5" /> : 'Reset Password'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default ResetPassword;