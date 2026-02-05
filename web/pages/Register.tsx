import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import * as authService from '../services/authService';
import { Shield, Loader2, Check, X, Sun, Moon } from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';

const SECURITY_QUESTIONS = [
  "What is your favorite color?",
  "What was the name of your first pet?",
  "In what city were you born?",
  "What is your mother's maiden name?",
  "What was the make of your first car?"
];

const Register: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [securityQuestion, setSecurityQuestion] = useState(SECURITY_QUESTIONS[0]);
  const [securityAnswer, setSecurityAnswer] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { theme, toggleTheme } = useTheme();

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
    
    // Length checks
    if (pass.length >= 8) score += 1;
    if (pass.length >= 12) score += 1;
    
    // Complexity checks
    if (/[0-9]/.test(pass)) score += 1;
    if (/[a-z]/.test(pass) && /[A-Z]/.test(pass)) score += 1;
    if (/[^A-Za-z0-9]/.test(pass)) score += 1; // Special char
    
    return score; // Max 5
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

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (!passValidation.length || !passValidation.number || !passValidation.letter) {
        setError('Password does not meet requirements');
        return;
    }

    if (!securityAnswer.trim()) {
        setError('Please provide an answer to the security question');
        return;
    }

    setLoading(true);
    
    try {
      await authService.register(username, password, securityQuestion, securityAnswer);
      // Redirect to login with success message instead of auto-login
      navigate('/login', { state: { success: 'Account created successfully! Please sign in.' } });
    } catch (err: any) {
      setError(err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

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
        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-white">Create your account</h2>
        <p className="mt-2 text-center text-sm text-gray-600 dark:text-gray-400">
          Already have an account?{' '}
          <Link to="/login" className="font-medium text-primary-600 hover:text-primary-500 dark:text-primary-400 dark:hover:text-primary-300">
            Sign in
          </Link>
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white dark:bg-gray-800 py-8 px-4 shadow sm:rounded-lg sm:px-10 border border-gray-100 dark:border-gray-700">
          <form className="space-y-6" onSubmit={handleSubmit}>
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Username
              </label>
              <div className="mt-1">
                <input
                  id="username"
                  name="username"
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="appearance-none block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                />
              </div>
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Password
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

               {/* Password requirements visualizer */}
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
                Confirm Password
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

            {/* Security Question Section */}
            <div>
              <label htmlFor="securityQuestion" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Security Question
              </label>
              <select
                id="securityQuestion"
                name="securityQuestion"
                className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 py-2 pl-3 pr-10 text-base focus:border-primary-500 focus:outline-none focus:ring-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                value={securityQuestion}
                onChange={(e) => setSecurityQuestion(e.target.value)}
              >
                {SECURITY_QUESTIONS.map((q) => (
                  <option key={q} value={q}>{q}</option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="securityAnswer" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Answer
              </label>
              <div className="mt-1">
                <input
                  id="securityAnswer"
                  name="securityAnswer"
                  type="text"
                  required
                  value={securityAnswer}
                  onChange={(e) => setSecurityAnswer(e.target.value)}
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

            <div className="flex gap-3">
              <button
                type="button"
                onClick={() => navigate('/login')}
                className="flex-1 flex justify-center py-2 px-4 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading}
                className="flex-1 flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? <Loader2 className="animate-spin h-5 w-5" /> : 'Create Account'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Register;