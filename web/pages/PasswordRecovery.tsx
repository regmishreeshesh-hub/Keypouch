import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const securityQuestionIndices = [2, 5, 8]; // Example: 3rd, 6th, 9th words

const PasswordRecovery: React.FC = () => {
  const [keywords, setKeywords] = useState(Array(6).fill(''));
  const [questions, setQuestions] = useState(Array(3).fill(''));
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [step, setStep] = useState(1);
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    try {
      // Call backend to verify keywords and questions, then reset password
      const res = await fetch('/api/admin/recover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          keywords: keywords.map(k => k.trim().toLowerCase()),
          questions: questions.map(q => q.trim().toLowerCase()),
          newPassword,
        })
      });
      if (!res.ok) throw new Error('Recovery failed. Check your keywords and answers.');
      setSuccess('Password reset successful! Redirecting to login...');
      setTimeout(() => navigate('/login'), 2000);
    } catch (err: any) {
      setError(err.message || 'Recovery failed');
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gray-50 dark:bg-gray-900 px-4">
      <div className="bg-white dark:bg-gray-800 p-8 rounded shadow-md w-full max-w-lg">
        <h2 className="text-2xl font-bold mb-4 text-gray-900 dark:text-white">Admin Password Recovery</h2>
        <div className="mb-4 text-gray-700 dark:text-gray-300">
          Enter any <span className="font-bold">6 of your 12 recovery keywords</span> (in any order) and answer the 3 security questions below. <br />
          <span className="text-red-600 dark:text-red-400 font-semibold">If you lose your recovery phrase, you will not be able to recover your account.</span>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-2 gap-2">
            {keywords.map((k, i) => (
              <input
                key={i}
                className="p-2 border rounded"
                placeholder={`Keyword ${i+1}`}
                value={k}
                onChange={e => {
                  const arr = [...keywords]; arr[i] = e.target.value; setKeywords(arr);
                }}
                required
              />
            ))}
          </div>
          <div className="mt-4 mb-2 font-semibold">Security Questions:</div>
          {securityQuestionIndices.map((idx, i) => (
            <input
              key={i}
              className="mb-2 p-2 border rounded w-full"
              placeholder={`What is your ${idx+1}${['st','nd','rd'][i] || 'th'} recovery word?`}
              value={questions[i]}
              onChange={e => {
                const arr = [...questions]; arr[i] = e.target.value; setQuestions(arr);
              }}
              required
            />
          ))}
          <input
            className="mb-2 p-2 border rounded w-full"
            type="password"
            placeholder="New Password"
            value={newPassword}
            onChange={e => setNewPassword(e.target.value)}
            required
          />
          {error && <div className="text-red-600 dark:text-red-400">{error}</div>}
          {success && <div className="text-green-600 dark:text-green-400">{success}</div>}
          <button
            className="w-full bg-primary-600 hover:bg-primary-700 text-white font-bold py-2 px-4 rounded"
            type="submit"
          >
            Reset Password
          </button>
        </form>
      </div>
    </div>
  );
};

export default PasswordRecovery;
