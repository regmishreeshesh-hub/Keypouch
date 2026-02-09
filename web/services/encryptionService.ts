/**
 * Encryption Service for KeyPouch
 * Implements AES-256-GCM and PBKDF2 for Zero-Knowledge Architecture
 */

const ITERATIONS = 100000;
const SALT_SIZE = 16;
const IV_SIZE = 12;

/**
 * Check if Web Crypto API is available
 */
function isCryptoAvailable(): boolean {
    return typeof window !== 'undefined' && !!window.crypto?.subtle;
}

/**
 * Initialize or verify crypto availability
 */
export async function initializeCrypto(): Promise<boolean> {
    try {
        if (typeof window === 'undefined') {
            console.warn('Window is undefined - likely SSR context');
            return false;
        }
        
        if (!window.crypto) {
            console.warn('window.crypto is undefined');
            return false;
        }
        
        if (!window.crypto.subtle) {
            console.warn('window.crypto.subtle is undefined');
            return false;
        }
        
        // Test the API by attempting a basic operation
        const testData = new TextEncoder().encode('test');
        const testKey = await window.crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );
        console.log('✓ Web Crypto API initialized successfully');
        return true;
    } catch (error) {
        console.error('✗ Web Crypto API initialization failed:', error);
        return false;
    }
}

/**
 * Derives a cryptographic key from a password and salt
 */
export async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey | null> {
    if (!isCryptoAvailable()) {
        console.warn('Web Crypto API not available');
        return null;
    }

    try {
        const encoder = new TextEncoder();
        const passwordData = encoder.encode(password);

        const baseKey = await window.crypto.subtle.importKey(
            'raw',
            passwordData,
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        return await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt as any,
                iterations: ITERATIONS,
                hash: 'SHA-256',
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    } catch (error) {
        console.error('Error deriving key:', error);
        return null;
    }
}

/**
 * Encrypts a string using a CryptoKey
 */
export async function encrypt(plaintext: string, key: CryptoKey | null): Promise<{ encrypted: string; iv: string; authTag: string } | null> {
    if (!key || !isCryptoAvailable()) {
        console.warn('Encryption not available');
        return null;
    }

    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        const iv = window.crypto.getRandomValues(new Uint8Array(IV_SIZE));

        const encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            data
        );

        const encryptedArray = new Uint8Array(encryptedBuffer);
        // AES-GCM in Web Crypto API appends the auth tag to the ciphertext
        const authTagSize = 16;
        const ciphertext = encryptedArray.slice(0, encryptedArray.length - authTagSize);
        const authTag = encryptedArray.slice(encryptedArray.length - authTagSize);

        return {
            encrypted: btoa(String.fromCharCode(...ciphertext)),
            iv: btoa(String.fromCharCode(...iv)),
            authTag: btoa(String.fromCharCode(...authTag)),
        };
    } catch (error) {
        console.error('Error encrypting data:', error);
        return null;
    }
}

/**
 * Decrypts a base64 string using a CryptoKey, iv, and authTag
 */
export async function decrypt(encrypted: string, iv: string, authTag: string, key: CryptoKey | null): Promise<string | null> {
    if (!key || !isCryptoAvailable()) {
        console.warn('Decryption not available');
        return null;
    }

    try {
        const ciphertext = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
        const ivArray = Uint8Array.from(atob(iv), c => c.charCodeAt(0));
        const authTagArray = Uint8Array.from(atob(authTag), c => c.charCodeAt(0));

        // Combine ciphertext and authTag for Web Crypto API
        const encryptedData = new Uint8Array(ciphertext.length + authTagArray.length);
        encryptedData.set(ciphertext);
        encryptedData.set(authTagArray, ciphertext.length);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ivArray },
            key,
            encryptedData
        );

        return new TextDecoder().decode(decryptedBuffer);
    } catch (error) {
        console.error('Error decrypting data:', error);
        return null;
    }
}

/**
 * Helper to get or derive the master key from sessionStorage
 * Note: In a real app, this should be handled via a more secure state management
 */
export async function getMasterKey(password?: string, username?: string): Promise<CryptoKey | null> {
    if (!isCryptoAvailable()) {
        console.warn('Web Crypto API not available for master key');
        return null;
    }

    try {
        if (password && username) {
            const salt = new TextEncoder().encode(username.padEnd(SALT_SIZE, '0'));
            const key = await deriveKey(password, salt);
            if (!key) return null;
            
            // Export and save to sessionStorage (for demo purposes)
            const exportedKey = await window.crypto.subtle.exportKey('raw', key);
            sessionStorage.setItem('masterKey', btoa(String.fromCharCode(...new Uint8Array(exportedKey))));
            return key;
        }

        const storedKey = sessionStorage.getItem('masterKey');
        if (storedKey) {
            try {
                const keyBuffer = Uint8Array.from(atob(storedKey), c => c.charCodeAt(0));
                return await window.crypto.subtle.importKey(
                    'raw',
                    keyBuffer,
                    { name: 'AES-GCM', length: 256 },
                    true,
                    ['encrypt', 'decrypt']
                );
            } catch (error) {
                console.error('Error importing stored key:', error);
                sessionStorage.removeItem('masterKey');
                return null;
            }
        }

        return null;
    } catch (error) {
        console.error('Error getting master key:', error);
        return null;
    }
}
