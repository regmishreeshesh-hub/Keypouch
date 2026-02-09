import React, { useState, useEffect } from 'react';
import Modal from './Modal';
import { Share2, Copy, Check, Clock, ShieldAlert, Loader2 } from 'lucide-react';
import * as secretService from '../services/secretService';
import * as encryptionService from '../services/encryptionService';

interface SharingModalProps {
    isOpen: boolean;
    onClose: () => void;
    secretId: number;
    secretTitle: string;
    decryptedData: any;
}

const SharingModal: React.FC<SharingModalProps> = ({ isOpen, onClose, secretId, secretTitle, decryptedData }) => {
    const [expiresIn, setExpiresIn] = useState('60'); // Minutes
    const [maxViews, setMaxViews] = useState(1);
    const [loading, setLoading] = useState(false);
    const [shareToken, setShareToken] = useState('');
    const [copied, setCopied] = useState(false);

    const handleCreateShare = async () => {
        setLoading(true);
        try {
            console.log('=== SHARE LINK CREATION START ===');
            console.log('Secret ID:', secretId);
            
            // Try client-side encryption if available
            let useClientEncryption = false;
            let encrypted: any = null;
            let shareKey: Uint8Array | null = null;
            
            if (typeof window !== 'undefined' && window.crypto?.subtle) {
                try {
                    console.log('✓ Web Crypto API available - using client-side encryption');
                    useClientEncryption = true;
                    
                    // Generate a random key for this share
                    shareKey = window.crypto.getRandomValues(new Uint8Array(32));
                    const key = await window.crypto.subtle.importKey(
                        'raw',
                        shareKey,
                        'AES-GCM',
                        true,
                        ['encrypt']
                    );
                    
                    encrypted = await encryptionService.encrypt(JSON.stringify(decryptedData), key);
                    if (!encrypted) throw new Error('Encryption failed');
                    console.log('✓ Data encrypted client-side');
                } catch (cryptoErr) {
                    console.warn('✗ Client-side encryption failed, falling back to server-side:', cryptoErr);
                    useClientEncryption = false;
                }
            } else {
                console.log('⚠ Web Crypto API not available - using server-side encryption');
            }
            
            console.log('Creating share link with API...');
            const payload: any = {
                expiresInMinutes: parseInt(expiresIn) || null,
                maxViews: maxViews,
            };
            
            if (useClientEncryption && encrypted) {
                // Client-side encrypted - include encryption details
                payload.encrypted_content = encrypted.encrypted;
                payload.content_iv = encrypted.iv;
                payload.content_auth_tag = encrypted.authTag;
            } else {
                // Server-side encryption - send raw data
                payload.secretData = decryptedData;
            }
            
            const data = await secretService.createShareLink(secretId, payload);
            console.log('✓ Share link created successfully');

            let shareUrl = `${data.token}`;
            
            // If we used client-side encryption, append the key as a fragment
            if (useClientEncryption && shareKey) {
                const keyBase64 = btoa(String.fromCharCode(...shareKey))
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=/g, '');
                shareUrl = `${data.token}#${keyBase64}`;
                console.log('Client-side encryption: key will be used for decryption');
            } else {
                console.log('Server-side encryption: data encrypted on server');
            }

            setShareToken(shareUrl);
            console.log('=== SHARE LINK CREATION SUCCESS ===');
        } catch (err) {
            console.error('=== SHARE LINK CREATION FAILED ===');
            console.error('Error:', err);
            alert(`Failed to create share link: ${err instanceof Error ? err.message : String(err)}`);
        } finally {
            setLoading(false);
        }
    };

    const shareUrl = shareToken ? `${window.location.origin}/#/share/${shareToken}` : '';

    const copyToClipboard = async () => {
        try {
            if (!navigator.clipboard) {
                const textArea = document.createElement("textarea");
                textArea.value = shareUrl;
                textArea.style.position = "fixed";
                textArea.style.left = "-999999px";
                textArea.style.top = "-999999px";
                document.body.appendChild(textArea);
                textArea.focus();
                textArea.select();
                document.execCommand('copy');
                textArea.remove();
            } else {
                await navigator.clipboard.writeText(shareUrl);
            }
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch (err) {
            console.error('Copy failed', err);
            alert('Failed to copy. Please copy the link manually.');
        }
    };

    return (
        <Modal isOpen={isOpen} onClose={onClose} title={`Share: ${secretTitle}`}>
            <div className="space-y-6 py-2">
                {!shareToken ? (
                    <>
                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 flex items-center gap-2">
                                    <Clock className="w-4 h-4" /> Expiration Time
                                </label>
                                <select
                                    value={expiresIn}
                                    onChange={(e) => setExpiresIn(e.target.value)}
                                    className="w-full p-2 border rounded dark:bg-gray-700 dark:text-white dark:border-gray-600"
                                >
                                    <option value="15">15 Minutes</option>
                                    <option value="60">1 Hour</option>
                                    <option value="1440">24 Hours</option>
                                    <option value="10080">7 Days</option>
                                    <option value="0">No Expiration</option>
                                </select>
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 flex items-center gap-2">
                                    <ShieldAlert className="w-4 h-4" /> View Limit
                                </label>
                                <div className="flex gap-4">
                                    <label className="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="radio"
                                            checked={maxViews === 1}
                                            onChange={() => setMaxViews(1)}
                                            className="text-primary-600"
                                        />
                                        <span className="text-sm dark:text-gray-300">One-time view</span>
                                    </label>
                                    <label className="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="radio"
                                            checked={maxViews === 0}
                                            onChange={() => setMaxViews(0)}
                                            className="text-primary-600"
                                        />
                                        <span className="text-sm dark:text-gray-300">Unlimited views</span>
                                    </label>
                                </div>
                            </div>
                        </div>

                        <button
                            onClick={handleCreateShare}
                            disabled={loading}
                            className="w-full bg-primary-600 text-white py-2 rounded-md font-bold hover:bg-primary-700 flex justify-center items-center gap-2 disabled:opacity-50"
                        >
                            {loading ? <Loader2 className="animate-spin w-5 h-5" /> : <Share2 className="w-5 h-5" />}
                            Generate Secure Link
                        </button>
                    </>
                ) : (
                    <div className="space-y-4">
                        <div className="p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
                            <p className="text-sm text-green-800 dark:text-green-300 font-medium mb-2">Secure link generated!</p>
                            <div className="flex gap-2">
                                <input
                                    readOnly
                                    value={shareUrl}
                                    className="flex-1 p-2 text-xs border rounded bg-white dark:bg-gray-800 dark:text-white dark:border-gray-700"
                                />
                                <button
                                    onClick={copyToClipboard}
                                    className="p-2 bg-primary-600 text-white rounded hover:bg-primary-700 transition-colors"
                                >
                                    {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                                </button>
                            </div>
                        </div>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                            {maxViews === 1
                                ? "⚠️ This link will be destroyed after the first access."
                                : "This link will remain active until it expires or is manually revoked."}
                        </p>
                        <button
                            onClick={() => setShareToken('')}
                            className="w-full py-2 text-sm text-gray-600 dark:text-gray-400 hover:underline"
                        >
                            Create another link
                        </button>
                    </div>
                )}
            </div>
        </Modal>
    );
};

export default SharingModal;
