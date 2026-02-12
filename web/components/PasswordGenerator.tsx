import React, { useState, useEffect } from 'react';
import { generatePassword, calculateStrength } from '../src/utils/passwordUtils';
import { RefreshCw, Copy, Check, ShieldCheck, ShieldAlert, Shield } from 'lucide-react';

interface PasswordGeneratorProps {
    onSelectPassword: (password: string) => void;
    onClose: () => void;
}

const PasswordGenerator: React.FC<PasswordGeneratorProps> = ({ onSelectPassword, onClose }) => {
    const [password, setPassword] = useState('');
    const [length, setLength] = useState(16);
    const [options, setOptions] = useState({
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: true,
    });
    const [copied, setCopied] = useState(false);

    // Generate password on mount or when options change
    useEffect(() => {
        handleGenerate();
    }, [length, options]);

    const handleGenerate = () => {
        // Ensure at least one option is selected
        if (!options.uppercase && !options.lowercase && !options.numbers && !options.symbols) {
            return;
        }
        const newPassword = generatePassword(length, options);
        setPassword(newPassword);
        setCopied(false);
    };

    const handleOptionChange = (key: keyof typeof options) => {
        setOptions((prev) => {
            const newOptions = { ...prev, [key]: !prev[key] };
            // Prevent unchecking the last option
            if (!newOptions.uppercase && !newOptions.lowercase && !newOptions.numbers && !newOptions.symbols) {
                return prev;
            }
            return newOptions;
        });
    };

    const handleCopy = () => {
        navigator.clipboard.writeText(password);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const handleUsePassword = () => {
        onSelectPassword(password);
        onClose();
    };

    const strength = calculateStrength(password);

    const getStrengthColor = () => {
        switch (strength) {
            case 'weak': return 'bg-red-500';
            case 'medium': return 'bg-yellow-500';
            case 'strong': return 'bg-green-500';
            case 'very-strong': return 'bg-green-600';
            default: return 'bg-gray-300';
        }
    };

    const getStrengthLabel = () => {
        switch (strength) {
            case 'weak': return 'Weak';
            case 'medium': return 'Medium';
            case 'strong': return 'Strong';
            case 'very-strong': return 'Very Strong';
            default: return '';
        }
    };

    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-4 border dark:border-gray-700 shadow-lg w-full max-w-sm">
            <h3 className="text-lg font-bold mb-4 dark:text-white flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-primary-600" /> Password Generator
            </h3>

            <div className="relative mb-4">
                <div className="w-full bg-gray-100 dark:bg-gray-900 p-3 rounded-md font-mono text-lg text-center break-all min-h-[52px] flex items-center justify-center dark:text-white">
                    {password}
                </div>
                <button
                    onClick={handleGenerate}
                    className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 text-gray-500 hover:text-primary-600 dark:hover:text-primary-400 transition-colors"
                    title="Regenerate"
                >
                    <RefreshCw className="w-4 h-4" />
                </button>
            </div>

            {/* Strength Indicator */}
            <div className="mb-4 flex items-center gap-2 text-xs">
                <span className="text-gray-500 w-16">Strength:</span>
                <div className="flex-1 h-1.5 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                    <div className={`h-full ${getStrengthColor()} transition-all duration-300`} style={{ width: strength === 'weak' ? '25%' : strength === 'medium' ? '50%' : strength === 'strong' ? '75%' : '100%' }}></div>
                </div>
                <span className="font-semibold dark:text-gray-300 w-20 text-right">{getStrengthLabel()}</span>
            </div>

            <div className="space-y-4 mb-6">
                <div>
                    <div className="flex justify-between text-xs text-gray-500 mb-1">
                        <span>Length: {length}</span>
                        <span>64</span>
                    </div>
                    <input
                        type="range"
                        min="6"
                        max="64"
                        value={length}
                        onChange={(e) => setLength(parseInt(e.target.value))}
                        className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer dark:bg-gray-700 accent-primary-600"
                    />
                </div>

                <div className="grid grid-cols-2 gap-2">
                    {Object.entries(options).map(([key, value]) => (
                        <label key={key} className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 cursor-pointer select-none">
                            <input
                                type="checkbox"
                                checked={value}
                                onChange={() => handleOptionChange(key as keyof typeof options)}
                                className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                            />
                            <span className="capitalize">{key}</span>
                        </label>
                    ))}
                </div>
            </div>

            <div className="flex gap-2">
                <button
                    onClick={handleCopy}
                    className="flex-1 py-2 px-4 border border-gray-300 dark:border-gray-600 rounded-md text-gray-700 dark:text-gray-300 font-medium hover:bg-gray-50 dark:hover:bg-gray-700 flex items-center justify-center gap-2 transition-colors"
                >
                    {copied ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
                    Copy
                </button>
                <button
                    onClick={handleUsePassword}
                    className="flex-1 py-2 px-4 bg-primary-600 text-white rounded-md font-medium hover:bg-primary-700 flex items-center justify-center gap-2 transition-colors shadow-sm"
                >
                    Use Password
                </button>
            </div>
        </div>
    );
};

export default PasswordGenerator;
