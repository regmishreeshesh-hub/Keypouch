export const generatePassword = (
    length: number = 16,
    options: {
        uppercase: boolean;
        lowercase: boolean;
        numbers: boolean;
        symbols: boolean;
    }
): string => {
    const charset = {
        uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        lowercase: 'abcdefghijklmnopqrstuvwxyz',
        numbers: '0123456789',
        symbols: '!@#$%^&*()_+~`|}{[]:;?><,./-=',
    };

    let chars = '';
    if (options.uppercase) chars += charset.uppercase;
    if (options.lowercase) chars += charset.lowercase;
    if (options.numbers) chars += charset.numbers;
    if (options.symbols) chars += charset.symbols;

    if (chars.length === 0) return '';

    let password = '';
    const array = new Uint32Array(length);
    window.crypto.getRandomValues(array);

    for (let i = 0; i < length; i++) {
        password += chars[array[i] % chars.length];
    }

    return password;
};

export const calculateStrength = (password: string): 'weak' | 'medium' | 'strong' | 'very-strong' => {
    let score = 0;
    if (!password) return 'weak';

    if (password.length > 8) score += 1;
    if (password.length > 12) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;

    if (score < 3) return 'weak';
    if (score < 4) return 'medium';
    if (score < 6) return 'strong';
    return 'very-strong';
};
