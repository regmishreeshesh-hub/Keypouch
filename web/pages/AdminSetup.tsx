import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Loader2, Building2, User, HelpCircle, CheckCircle } from 'lucide-react';
import * as authService from '../services/authService';

const SECURITY_QUESTIONS = [
  "What is your favorite color?",
  "What was the name of your first pet?",
  "In what city were you born?",
  "What is your mother's maiden name?",
  "What was the make of your first car?"
];

interface AdminRegistrationData {
  username: string;
  password: string;
  confirmPassword: string;
  securityQuestion: string;
  securityAnswer: string;
  companyName: string;
}

const AdminSetup: React.FC = () => {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [formData, setFormData] = useState<AdminRegistrationData>({
    username: '',
    password: '',
    confirmPassword: '',
    securityQuestion: SECURITY_QUESTIONS[0],
    securityAnswer: '',
    companyName: ''
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [companyLogo, setCompanyLogo] = useState<string | null>(null);
  const [adminExists, setAdminExists] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    // Check if real admin exists
    const checkAdmin = async () => {
      try {
        const res = await fetch('/api/admin/check');
        const data = await res.json();
        setAdminExists(data.exists);
      } catch {
        setAdminExists(false);
      }
    };
    checkAdmin();
  }, []);

  const getStepError = (targetStep: number) => {
    if (targetStep === 1) {
      if (!formData.companyName) return 'Company name is required';
      return '';
    }
    if (targetStep === 2) {
      if (!formData.username) return 'Admin username is required';
      if (!formData.password) return 'Password is required';
      if (!formData.confirmPassword) return 'Please confirm your password';
      if (formData.password.length < 8) return 'Password must be at least 8 characters long';
      if (formData.password !== formData.confirmPassword) return 'Passwords do not match';
      return '';
    }
    if (targetStep === 3) {
      if (!formData.securityQuestion) return 'Security question is required';
      if (!formData.securityAnswer) return 'Security answer is required';
      return '';
    }
    return '';
  };

  const canGoNext = (currentStep: 1 | 2 | 3) => {
    if (currentStep === 1) return getStepError(1) === '';
    if (currentStep === 2) return getStepError(2) === '';
    return false;
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleLogoChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (ev) => {
        setCompanyLogo(ev.target?.result as string);
        localStorage.setItem('companyLogo', ev.target?.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleNext = () => {
    setError('');
    const err = getStepError(step);
    if (err) {
      setError(err);
      return;
    }
    if (step < 3) setStep((step + 1) as 2 | 3);
  };

  const handleBack = () => {
    setError('');
    if (step > 1) setStep((step - 1) as 1 | 2);
  };

  const handleSubmit = async () => {
    setLoading(true);
    setError('');
    setSuccess('');

    // Validation
    if (!formData.username || !formData.password || !formData.confirmPassword || 
        !formData.securityQuestion || !formData.securityAnswer || !formData.companyName) {
      setError('All fields are required');
      setLoading(false);
      return;
    }

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters long');
      setLoading(false);
      return;
    }

    try {
      const data = await authService.registerAdmin({
        username: formData.username,
        password: formData.password,
        securityQuestion: formData.securityQuestion,
        securityAnswer: formData.securityAnswer,
        companyName: formData.companyName,
      });

      // Store auth data
      localStorage.setItem('token', data.token);
      localStorage.setItem('username', data.username);
      localStorage.setItem('role', data.role);
      localStorage.setItem('is_demo', (data.is_demo || false).toString());
      localStorage.setItem('must_reset_password', (data.must_reset_password || false).toString());

      setSuccess('Admin account created successfully! Redirecting to login...');
      
      setTimeout(() => {
        navigate('/login');
      }, 2000);

    } catch (err: any) {
      setError(err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  if (adminExists) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
        <div className="bg-white dark:bg-gray-800 p-8 rounded shadow-md w-full max-w-md text-center">
          <h2 className="text-2xl font-bold mb-4 text-gray-900 dark:text-white">Admin Setup Unavailable</h2>
          <p className="text-gray-700 dark:text-gray-300 mb-4">An admin user has already been created for this company. Please contact support if you need to reset admin access.</p>
          <a href="/login" className="text-primary-600 hover:text-primary-700 font-bold">Go to Login</a>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center">
          <div className="rounded-full bg-primary-600 p-3">
            <Shield className="h-10 w-10 text-white" />
          </div>
        </div>
        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-white">
          Guided Admin Setup
        </h2>
        <p className="mt-2 text-center text-sm text-gray-600 dark:text-gray-400">
          Create your organization admin in 3 quick steps
        </p>
        <div className="mt-4 text-center">
          <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
            <Building2 className="w-3 h-3 mr-1" />
            One-time setup
          </span>
        </div>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white dark:bg-gray-800 py-8 px-4 shadow sm:rounded-lg sm:px-10 border border-gray-100 dark:border-gray-700">
          {success && (
            <div className="rounded-md bg-green-50 dark:bg-green-900/20 p-4 mb-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <CheckCircle className="h-5 w-5 text-green-400" aria-hidden="true" />
                </div>
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-green-800 dark:text-green-300">{success}</h3>
                </div>
              </div>
            </div>
          )}

          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <div className={`h-8 w-8 rounded-full flex items-center justify-center text-sm font-semibold ${step >= 1 ? 'bg-primary-600 text-white' : 'bg-gray-200 text-gray-600 dark:bg-gray-700 dark:text-gray-300'}`}>1</div>
              <div className="text-xs font-medium text-gray-700 dark:text-gray-300">Organization</div>
            </div>
            <div className="flex-1 mx-3 h-px bg-gray-200 dark:bg-gray-700" />
            <div className="flex items-center gap-2">
              <div className={`h-8 w-8 rounded-full flex items-center justify-center text-sm font-semibold ${step >= 2 ? 'bg-primary-600 text-white' : 'bg-gray-200 text-gray-600 dark:bg-gray-700 dark:text-gray-300'}`}>2</div>
              <div className="text-xs font-medium text-gray-700 dark:text-gray-300">Admin</div>
            </div>
            <div className="flex-1 mx-3 h-px bg-gray-200 dark:bg-gray-700" />
            <div className="flex items-center gap-2">
              <div className={`h-8 w-8 rounded-full flex items-center justify-center text-sm font-semibold ${step >= 3 ? 'bg-primary-600 text-white' : 'bg-gray-200 text-gray-600 dark:bg-gray-700 dark:text-gray-300'}`}>3</div>
              <div className="text-xs font-medium text-gray-700 dark:text-gray-300">Recovery</div>
            </div>
          </div>

          <form
            className="space-y-6"
            onSubmit={(e) => {
              e.preventDefault();
              if (step < 3) {
                handleNext();
              } else {
                const err = getStepError(3);
                if (err) {
                  setError(err);
                  return;
                }
                handleSubmit();
              }
            }}
          >
            <div>
              {step === 1 && (
                <>
                  <label htmlFor="companyLogo" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Company Logo (optional)
                  </label>
                  <div className="mt-1">
                    <input
                      id="companyLogo"
                      name="companyLogo"
                      type="file"
                      accept="image/*"
                      onChange={handleLogoChange}
                      className="appearance-none block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                    {companyLogo && (
                      <div className="mt-3 flex items-center gap-3">
                        <img src={companyLogo} alt="Company logo preview" className="h-10 w-10 rounded-full object-cover border border-gray-300 dark:border-gray-600" />
                        <div className="text-xs text-gray-500 dark:text-gray-400">Saved for login screen</div>
                      </div>
                    )}
                  </div>
                </>
              )}
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

            {step === 1 && (
              <div>
                <label htmlFor="companyName" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Company Name
                </label>
                <div className="mt-1">
                  <input
                    id="companyName"
                    name="companyName"
                    type="text"
                    required
                    value={formData.companyName}
                    onChange={handleInputChange}
                    className="appearance-none block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    placeholder="Your company name"
                  />
                </div>
              </div>
            )}

            {step === 2 && (
              <div>
                <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Admin Username
                </label>
                <div className="mt-1">
                  <input
                    id="username"
                    name="username"
                    type="text"
                    required
                    value={formData.username}
                    onChange={handleInputChange}
                    className="appearance-none block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    placeholder="admin@yourcompany"
                  />
                </div>
              </div>
            )}

            {step === 2 && (
              <>
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
                      value={formData.password}
                      onChange={handleInputChange}
                      className="appearance-none block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                      placeholder="Min. 8 characters"
                    />
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
                      value={formData.confirmPassword}
                      onChange={handleInputChange}
                      className="appearance-none block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                      placeholder="Re-enter password"
                    />
                  </div>
                </div>
              </>
            )}

            {step === 3 && (
              <div className="rounded-md bg-gray-50 dark:bg-gray-900/30 border border-gray-200 dark:border-gray-700 p-4">
                <div className="text-sm font-medium text-gray-900 dark:text-white mb-2">Review</div>
                <div className="text-sm text-gray-700 dark:text-gray-300 flex items-center gap-2">
                  <Building2 className="w-4 h-4" />
                  <span className="font-medium">Company:</span> {formData.companyName || '—'}
                </div>
                <div className="text-sm text-gray-700 dark:text-gray-300 flex items-center gap-2 mt-1">
                  <User className="w-4 h-4" />
                  <span className="font-medium">Admin:</span> {formData.username || '—'}
                </div>
              </div>
            )}

            {step === 3 && (
              <>
                <div>
                  <label htmlFor="securityQuestion" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Security Question
                  </label>
                  <div className="mt-1">
                    <select
                      id="securityQuestion"
                      name="securityQuestion"
                      required
                      value={formData.securityQuestion}
                      onChange={handleInputChange}
                      className="appearance-none block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    >
                      {SECURITY_QUESTIONS.map((q) => (
                        <option key={q} value={q}>{q}</option>
                      ))}
                    </select>
                    <p className="mt-2 text-xs text-gray-500 dark:text-gray-400 flex items-center gap-1">
                      <HelpCircle className="w-3.5 h-3.5" />
                      Used to verify you for password recovery.
                    </p>
                  </div>
                </div>

                <div>
                  <label htmlFor="securityAnswer" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Security Answer
                  </label>
                  <div className="mt-1">
                    <input
                      id="securityAnswer"
                      name="securityAnswer"
                      type="text"
                      required
                      value={formData.securityAnswer}
                      onChange={handleInputChange}
                      className="appearance-none block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                      placeholder="Your security answer"
                    />
                  </div>
                </div>
              </>
            )}

            <div>
              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={handleBack}
                  disabled={loading || step === 1}
                  className="flex-1 flex justify-center py-2 px-4 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Back
                </button>
                {step < 3 ? (
                  <button
                    type="submit"
                    disabled={loading || !canGoNext(step)}
                    className="flex-1 flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Next
                  </button>
                ) : (
                  <button
                    type="submit"
                    disabled={loading}
                    className="flex-1 flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {loading ? <Loader2 className="animate-spin h-5 w-5" /> : 'Create Admin Account'}
                  </button>
                )}
              </div>
            </div>
          </form>

          <div className="mt-6">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-300 dark:border-gray-600" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-white dark:bg-gray-800 text-gray-500 dark:text-gray-400">
                  Demo Access
                </span>
              </div>
            </div>

            <div className="mt-6 text-center">
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                Want to try the demo first?
              </p>
              <Link
                to="/login"
                className="w-full flex justify-center py-2 px-4 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
              >
                Use Demo Account
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminSetup;
