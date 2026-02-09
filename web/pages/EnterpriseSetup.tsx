import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
// import bip39 or use a secure RNG for real implementation

const generateRecoveryPhrase = () => {
  // Placeholder: Replace with secure 12-word mnemonic generator (e.g., bip39)
  const words = [];
  for (let i = 0; i < 12; i++) {
    words.push('word' + (i + 1));
  }
  return words;
};

const EnterpriseSetup: React.FC = () => {
  const [step, setStep] = useState(1);
  const [companyName, setCompanyName] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [securityQuestions, setSecurityQuestions] = useState([
    { question: '', answer: '' },
    { question: '', answer: '' },
    { question: '', answer: '' },
  ]);
  const [recoveryPhrase, setRecoveryPhrase] = useState<string[]>([]);
  const [confirmed, setConfirmed] = useState(false);
  const navigate = useNavigate();

  const handleNext = () => {
    if (step === 1) {
      setRecoveryPhrase(generateRecoveryPhrase());
    }
    setStep(step + 1);
  };

  const handleConfirm = () => {
    setConfirmed(true);
    // TODO: Submit to backend
    setTimeout(() => navigate('/login'), 2000);
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gray-50 dark:bg-gray-900 px-4">
      <div className="bg-white dark:bg-gray-800 p-8 rounded shadow-md w-full max-w-lg">
        {step === 1 && (
          <>
            <h2 className="text-2xl font-bold mb-4 text-gray-900 dark:text-white">Enterprise Admin Setup</h2>
            <input className="mb-2 w-full p-2 border rounded" placeholder="Company Name" value={companyName} onChange={e => setCompanyName(e.target.value)} />
            <input className="mb-2 w-full p-2 border rounded" placeholder="Admin Username" value={username} onChange={e => setUsername(e.target.value)} />
            <input className="mb-2 w-full p-2 border rounded" type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} />
            <div className="mb-2">Security Questions:</div>
            {securityQuestions.map((q, i) => (
              <div key={i} className="mb-2 flex gap-2">
                <input className="flex-1 p-2 border rounded" placeholder={`Question ${i+1}`} value={q.question} onChange={e => {
                  const arr = [...securityQuestions]; arr[i].question = e.target.value; setSecurityQuestions(arr);
                }} />
                <input className="flex-1 p-2 border rounded" placeholder="Answer" value={q.answer} onChange={e => {
                  const arr = [...securityQuestions]; arr[i].answer = e.target.value; setSecurityQuestions(arr);
                }} />
              </div>
            ))}
            <button className="w-full bg-primary-600 hover:bg-primary-700 text-white font-bold py-2 px-4 rounded mt-4" onClick={handleNext}>
              Next: Generate Recovery Phrase
            </button>
          </>
        )}
        {step === 2 && (
          <>
            <h2 className="text-2xl font-bold mb-4 text-gray-900 dark:text-white">Your 12-Word Recovery Phrase</h2>
            <div className="grid grid-cols-3 gap-2 mb-4">
              {recoveryPhrase.map((word, i) => (
                <div key={i} className="bg-gray-100 dark:bg-gray-700 rounded p-2 text-center font-mono">{word}</div>
              ))}
            </div>
            <div className="text-red-600 dark:text-red-400 mb-2 font-semibold">
              Store these 12 words securely. You will never see them again. If lost, account recovery is impossible.
            </div>
            <label className="flex items-center mb-4">
              <input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} className="mr-2" />
              I have securely stored my recovery phrase.
            </label>
            <button className="w-full bg-primary-600 hover:bg-primary-700 text-white font-bold py-2 px-4 rounded" disabled={!confirmed} onClick={handleConfirm}>
              Complete Setup
            </button>
          </>
        )}
        {confirmed && (
          <div className="mt-4 text-green-600 dark:text-green-400 font-bold text-center">
            Admin account created! Redirecting to login...
          </div>
        )}
      </div>
    </div>
  );
};

export default EnterpriseSetup;
