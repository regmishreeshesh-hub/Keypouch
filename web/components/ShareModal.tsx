import React, { useState, useEffect } from 'react';
import { Share2, Copy, Check, Loader2, AlertCircle, Clock, Link as LinkIcon } from 'lucide-react';
import * as secretService from '../../services/secretService';

interface ShareModalProps {
  isOpen: boolean;
  onClose: () => void;
  secretId: number;
  secretTitle: string;
}

interface ShareConfig {
  expiresInMinutes: number | null;
  maxViews: number;
  allowedEmails: string[];
}

export const ShareModal: React.FC<ShareModalProps> = ({
  isOpen,
  onClose,
  secretId,
  secretTitle,
}) => {
  const [shareConfig, setShareConfig] = useState<ShareConfig>({
    expiresInMinutes: 1440,  // 24 hours default
    maxViews: 1,             // One-time view default
    allowedEmails: [],
  });
  
  const [shareLink, setShareLink] = useState<string>('');
  const [isLoading, setIsLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [expirationTimer, setExpirationTimer] = useState<string>('');
  const [shareCreated, setShareCreated] = useState(false);

  // Calculate and update expiration timer
  useEffect(() => {
    if (!shareCreated || !shareConfig.expiresInMinutes) return;

    const interval = setInterval(() => {
      const expiresAt = new Date(Date.now() + shareConfig.expiresInMinutes * 60000);
      const now = new Date();
      const diff = expiresAt.getTime() - now.getTime();

      if (diff <= 0) {
        setExpirationTimer('Expired');
        clearInterval(interval);
      } else {
        const hours = Math.floor(diff / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((diff % (1000 * 60)) / 1000);
        
        setExpirationTimer(`${hours}h ${minutes}m ${seconds}s`);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [shareCreated, shareConfig.expiresInMinutes]);

  const handleCreateShare = async () => {
    setIsLoading(true);
    try {
      const response = await secretService.createShareLink(secretId, {
        expiresInMinutes: shareConfig.expiresInMinutes,
        maxViews: shareConfig.maxViews,
        allowedEmails: shareConfig.allowedEmails.length > 0 ? shareConfig.allowedEmails : undefined,
      });

      setShareLink(response.shareUrl);
      setShareCreated(true);
    } catch (error) {
      alert('Failed to create share link: ' + (error as Error).message);
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(shareLink);
      setCopied(true);
      
      // Auto-clear copy status after 2 seconds
      setTimeout(() => setCopied(false), 2000);
      
      // Auto-clear clipboard after 60 seconds
      setTimeout(async () => {
        await navigator.clipboard.writeText('');
      }, 60000);
    } catch (error) {
      alert('Failed to copy to clipboard');
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-8 max-w-md w-full m-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center gap-3 mb-6">
          <Share2 className="w-6 h-6 text-primary-600" />
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Share Secret</h2>
        </div>

        <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">
          Sharing: <span className="font-semibold text-gray-900 dark:text-white">{secretTitle}</span>
        </p>

        {!shareCreated ? (
          <div className="space-y-6">
            {/* Expiration Settings */}
            <div>
              <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
                ⏱️ Expiration
              </label>
              <div className="space-y-2">
                {[
                  { label: '1 Hour', value: 60 },
                  { label: '24 Hours', value: 1440 },
                  { label: '7 Days', value: 10080 },
                  { label: 'No Expiration', value: null },
                ].map(option => (
                  <label key={option.label} className="flex items-center gap-3 cursor-pointer">
                    <input
                      type="radio"
                      name="expiration"
                      checked={shareConfig.expiresInMinutes === option.value}
                      onChange={() => setShareConfig({ ...shareConfig, expiresInMinutes: option.value })}
                      className="w-4 h-4"
                    />
                    <span className="text-gray-700 dark:text-gray-300">{option.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* View Restriction */}
            <div>
              <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
                👁️ View Options
              </label>
              <div className="space-y-2">
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="radio"
                    name="views"
                    checked={shareConfig.maxViews === 1}
                    onChange={() => setShareConfig({ ...shareConfig, maxViews: 1 })}
                    className="w-4 h-4"
                  />
                  <span className="text-gray-700 dark:text-gray-300">
                    One-Time View (destroy after access)
                  </span>
                </label>
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="radio"
                    name="views"
                    checked={shareConfig.maxViews === 999999}
                    onChange={() => setShareConfig({ ...shareConfig, maxViews: 999999 })}
                    className="w-4 h-4"
                  />
                  <span className="text-gray-700 dark:text-gray-300">
                    Unlimited Views
                  </span>
                </label>
              </div>
              <p className="text-xs text-gray-500 dark:text-gray-500 mt-2">
                ⚠️ One-time view secrets are cryptographically destroyed after first access
              </p>
            </div>

            {/* Action Buttons */}
            <div className="flex gap-3 pt-4">
              <button
                onClick={handleCreateShare}
                disabled={isLoading}
                className="flex-1 bg-primary-600 text-white py-2 rounded-md font-semibold hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <LinkIcon className="w-4 h-4" />}
                {isLoading ? 'Creating...' : 'Create Share Link'}
              </button>
              <button
                onClick={onClose}
                className="px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          /* Share Created View */
          <div className="space-y-6">
            <div className="bg-green-50 dark:bg-green-900/30 border border-green-200 dark:border-green-800 rounded-lg p-4">
              <div className="flex items-center gap-2 text-green-700 dark:text-green-400 mb-2">
                <Check className="w-5 h-5" />
                <span className="font-semibold">Share Link Created</span>
              </div>
              <p className="text-sm text-green-600 dark:text-green-300">
                Share link is ready to use
              </p>
            </div>

            {/* Share URL */}
            <div>
              <label className="block text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase mb-2">
                Share Link
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={shareLink}
                  readOnly
                  className="flex-1 p-2 border border-gray-300 dark:border-gray-600 rounded bg-gray-50 dark:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-mono"
                />
                <button
                  onClick={copyToClipboard}
                  className="px-3 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 flex items-center gap-2"
                >
                  {copied ? (
                    <>
                      <Check className="w-4 h-4" />
                      Copied
                    </>
                  ) : (
                    <>
                      <Copy className="w-4 h-4" />
                      Copy
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Expiration Timer */}
            <div>
              <label className="block text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase mb-2">
                Expiration Timer
              </label>
              <div className="flex items-center gap-2 bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-800 rounded p-3">
                <Clock className="w-5 h-5 text-yellow-600 dark:text-yellow-400" />
                <span className="font-mono text-yellow-700 dark:text-yellow-300 font-semibold">
                  {expirationTimer}
                </span>
              </div>
            </div>

            {/* Share Settings Summary */}
            <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4 space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-gray-600 dark:text-gray-400">View Limit:</span>
                <span className="font-semibold text-gray-900 dark:text-white">
                  {shareConfig.maxViews === 1 ? '1 (One-Time)' : 'Unlimited'}
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-600 dark:text-gray-400">Security:</span>
                <span className="font-semibold text-gray-900 dark:text-white">
                  AES-256-GCM Encrypted
                </span>
              </div>
            </div>

            {/* Security Notice */}
            <div className="bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
              <div className="flex gap-3">
                <AlertCircle className="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-semibold text-blue-700 dark:text-blue-300 mb-1">
                    End-to-End Encrypted
                  </p>
                  <p className="text-xs text-blue-600 dark:text-blue-400">
                    This share link uses zero-knowledge encryption. The server cannot see the secret content.
                    {shareConfig.maxViews === 1 && ' The link is destroyed after first access.'}
                  </p>
                </div>
              </div>
            </div>

            {/* Close Button */}
            <button
              onClick={onClose}
              className="w-full bg-primary-600 text-white py-2 rounded-md font-semibold hover:bg-primary-700"
            >
              Close
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default ShareModal;
