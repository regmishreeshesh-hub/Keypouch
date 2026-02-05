import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import * as authService from '../services/authService';
import { Shield, Loader2, ArrowLeft, Sun, Moon, Mail, Lock } from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';

type Step = 'USERNAME' | 'SECURITY_QUESTION' | 'SUCCESS';

const ForgotPassword: React.FC = () => {
  const [step, setStep] = useState<Step>('USERNAME');
  const [username, setUsername] = useState('');
  const [fetchedQuestion, setFetchedQuestion] = useState('');
  const [securityAnswer, setSecurityAnswer] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [demoToken, setDemoToken] = useState<string | null>(null);
  const { theme, toggleTheme } = useTheme();

  const handleUsernameSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    try {
      const data = await authService.getSecurityQuestion(username);
      setFetchedQuestion(data.question);
      setStep('SECURITY_QUESTION');
    } catch (err: any) {
       // For security, generally we shouldn't reveal if user exists. 
       // However, for this specific Security Question flow, we must know if we can ask a question.
       // In a real app, you might fall back to "Send Email" flow if no question exists.
       setError('User not found or no security configuration enabled.');
    } finally {
      setLoading(false);
    }
  };

  const handleAnswerSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
        const response = await authService.verifySecurityAnswer(username, securityAnswer);
        setDemoToken(response.token);
        setStep('SUCCESS');
    } catch (err: any) {
        setError('Incorrect answer.');
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
        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-white">Reset Password</h2>
        <p className="mt-2 text-center text-sm text-gray-600 dark:text-gray-400">
            {step === 'USERNAME' && "Enter your username to verify identity"}
            {step === 'SECURITY_QUESTION' && "Answer your security question"}
            {step === 'SUCCESS' && "Verification Successful"}
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white dark:bg-gray-800 py-8 px-4 shadow sm:rounded-lg sm:px-10 border border-gray-100 dark:border-gray-700">
          
          {step === 'USERNAME' && (
              <form className="space-y-6" onSubmit={handleUsernameSubmit}>
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
                      placeholder="Enter your username"
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
                    className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50"
                  >
                    {loading ? <Loader2 className="animate-spin h-5 w-5" /> : 'Continue'}
                  </button>
                </div>
                
                <div className="text-center">
                    <Link to="/login" className="font-medium text-sm text-primary-600 hover:text-primary-500 dark:text-primary-400 flex items-center justify-center gap-1">
                        <ArrowLeft className="w-4 h-4" /> Back to Login
                    </Link>
                </div>
              </form>
          )}

          {step === 'SECURITY_QUESTION' && (
              <form className="space-y-6" onSubmit={handleAnswerSubmit}>
                <div>
                  <label className="block text-sm font-medium text-gray-500 dark:text-gray-400">
                    Security Question:
                  </label>
                  <p className="mt-1 text-lg font-medium text-gray-900 dark:text-white">
                      {fetchedQuestion}
                  </p>
                </div>

                <div>
                    <label htmlFor="answer" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                        Answer
                    </label>
                    <div className="mt-1">
                        <input
                        id="answer"
                        name="answer"
                        type="text"
                        required
                        value={securityAnswer}
                        onChange={(e) => setSecurityAnswer(e.target.value)}
                        className="appearance-none block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                        placeholder="Your answer"
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
                        onClick={() => setStep('USERNAME')}
                        className="flex-1 justify-center py-2 px-4 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none"
                    >
                        Back
                    </button>
                    <button
                        type="submit"
                        disabled={loading}
                        className="flex-1 justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50"
                    >
                        {loading ? <Loader2 className="animate-spin h-5 w-5" /> : 'Verify'}
                    </button>
                </div>
              </form>
          )}

          {step === 'SUCCESS' && (
              <div className="text-center">
                  <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 dark:bg-green-900/30 mb-4">
                      <Lock className="h-6 w-6 text-green-600 dark:text-green-400" />
                  </div>
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white">Identity Verified</h3>
                  <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                      You can now reset your password.
                  </p>
                  
                  {demoToken && (
                       <div className="mt-6 p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-md border border-yellow-200 dark:border-yellow-700 text-left">
                           <p className="text-xs font-bold text-yellow-800 dark:text-yellow-200 mb-2 uppercase tracking-wide">Development Mode</p>
                           <p className="text-xs text-yellow-700 dark:text-yellow-300 mb-3">Since we are simulating the reset flow:</p>
                           <Link to={`/reset-password?token=${demoToken}`} className="block text-center w-full py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none">
                               Proceed to Reset Password
                           </Link>
                       </div>
                  )}

                  {!demoToken && (
                      <p className="text-red-500">Error generating token.</p>
                  )}
              </div>
          )}

        </div>
      </div>
    </div>
  );
};

export default ForgotPassword;