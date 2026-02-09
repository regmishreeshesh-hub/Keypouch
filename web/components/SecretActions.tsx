import React, { useState } from 'react';
import { Share2, Eye, Copy, Edit2, Trash2, Check, AlertCircle, Loader2 } from 'lucide-react';
import ShareModal from './ShareModal';
import * as secretService from '../services/secretService';

interface SecretActionsProps {
  secretId: number;
  secretTitle: string;
  secretContent?: string;
  secretType?: string;
  onEdit?: () => void;
  onDelete?: () => void;
  onRefresh?: () => void;
  userRole?: 'view' | 'modify' | 'full-access' | 'admin';
}

export const SecretActions: React.FC<SecretActionsProps> = ({
  secretId,
  secretTitle,
  secretContent = '••••••••••••••••',
  secretType = 'password',
  onEdit,
  onDelete,
  onRefresh,
  userRole = 'view',
}) => {
  const [isShareModalOpen, setIsShareModalOpen] = useState(false);
  const [showViewModal, setShowViewModal] = useState(false);
  const [revealedContent, setRevealedContent] = useState(false);
  const [copied, setCopied] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [deletingSecretId, setDeletingSecretId] = useState<number | null>(null);
  const [notificationMessage, setNotificationMessage] = useState<string>('');

  const canEdit = userRole === 'modify' || userRole === 'full-access' || userRole === 'admin';
  const canDelete = userRole === 'full-access' || userRole === 'admin';
  const canShare = userRole === 'full-access' || userRole === 'admin';

  const handleCopyToClipboard = async () => {
    if (!secretContent || secretContent.includes('•')) {
      setNotificationMessage('ℹ️ Click View first to reveal the secret');
      return;
    }

    try {
      await navigator.clipboard.writeText(secretContent);
      setCopied(true);
      
      // Log copy action (without content)
      try {
        await secretService.logSecretAction('copy', secretId);
      } catch (err) {
        console.error('Failed to log copy action:', err);
      }

      setNotificationMessage('✓ Copied to clipboard');
      
      // Reset copy status
      setTimeout(() => setCopied(false), 2000);
      
      // Auto-clear clipboard after 60 seconds
      setTimeout(async () => {
        await navigator.clipboard.writeText('');
      }, 60000);
    } catch (error) {
      setNotificationMessage('❌ Failed to copy to clipboard');
    }
  };

  const handleViewSecret = async () => {
    if (revealedContent) {
      setRevealedContent(false);
      setShowViewModal(false);
      return;
    }

    setIsLoading(true);
    try {
      // Log view action
      await secretService.logSecretAction('view', secretId);
      setRevealedContent(true);
      setShowViewModal(true);
    } catch (error) {
      setNotificationMessage('❌ Failed to view secret');
      setIsLoading(false);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDelete = async () => {
    setDeletingSecretId(secretId);
    setIsLoading(true);
    try {
      await secretService.deleteSecret(secretId);
      setNotificationMessage('✓ Secret deleted successfully');
      setDeleteConfirmOpen(false);
      
      // Refresh parent component after short delay
      setTimeout(() => {
        onRefresh?.();
      }, 1000);
    } catch (error) {
      setNotificationMessage('❌ Failed to delete secret');
    } finally {
      setIsLoading(false);
      setDeletingSecretId(null);
    }
  };

  return (
    <>
      <div className="flex gap-2 flex-wrap">
        {/* View Button */}
        <button
          onClick={handleViewSecret}
          disabled={isLoading}
          className="p-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors disabled:opacity-50"
          title="View Secret"
        >
          {isLoading ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : revealedContent ? (
            <Eye className="w-4 h-4 text-primary-600" />
          ) : (
            <Eye className="w-4 h-4" />
          )}
        </button>

        {/* Copy Button */}
        <button
          onClick={handleCopyToClipboard}
          disabled={!revealedContent || isLoading}
          className="p-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          title="Copy to Clipboard (60s auto-clear)"
        >
          {copied ? (
            <Check className="w-4 h-4 text-green-600" />
          ) : (
            <Copy className="w-4 h-4" />
          )}
        </button>

        {/* Share Button (Admin/Full-Access only) */}
        {canShare && (
          <button
            onClick={() => setIsShareModalOpen(true)}
            className="p-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
            title="Share Secret (One-Time or Time-Limited)"
          >
            <Share2 className="w-4 h-4" />
          </button>
        )}

        {/* Edit Button (Modify/Admin only) */}
        {canEdit && (
          <button
            onClick={onEdit}
            className="p-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
            title="Edit Secret"
          >
            <Edit2 className="w-4 h-4" />
          </button>
        )}

        {/* Delete Button (Full-Access/Admin only) */}
        {canDelete && (
          <button
            onClick={() => setDeleteConfirmOpen(true)}
            className="p-2 text-gray-600 dark:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
            title="Delete Secret"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Notification */}
      {notificationMessage && (
        <div className="mt-2 text-xs text-gray-600 dark:text-gray-400 p-2 bg-gray-50 dark:bg-gray-700 rounded">
          {notificationMessage}
        </div>
      )}

      {/* View Secret Modal */}
      {showViewModal && revealedContent && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full m-4">
            <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-4">
              {secretTitle}
            </h3>
            <div className="bg-gray-50 dark:bg-gray-700 p-4 rounded mb-4 break-all">
              <code className="text-sm font-mono text-gray-900 dark:text-gray-100">
                {secretContent}
              </code>
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleCopyToClipboard}
                className="flex-1 bg-primary-600 text-white py-2 rounded font-semibold hover:bg-primary-700 flex items-center justify-center gap-2"
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
              <button
                onClick={() => {
                  setRevealedContent(false);
                  setShowViewModal(false);
                }}
                className="px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                Close
              </button>
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-4 text-center">
              ✓ This action was logged for audit compliance
            </p>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirmOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-sm w-full m-4">
            <div className="flex items-center gap-3 mb-4">
              <AlertCircle className="w-6 h-6 text-red-600" />
              <h3 className="text-lg font-bold text-gray-900 dark:text-white">
                Delete Secret
              </h3>
            </div>
            <p className="text-gray-700 dark:text-gray-300 mb-6">
              Permanently delete <span className="font-semibold">{secretTitle}</span>?
            </p>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">
              ⚠️ This action cannot be undone. All active share links will be revoked.
            </p>
            <div className="flex gap-3">
              <button
                onClick={handleDelete}
                disabled={isLoading || deletingSecretId !== null}
                className="flex-1 bg-red-600 text-white py-2 rounded font-semibold hover:bg-red-700 disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Deleting...
                  </>
                ) : (
                  <>
                    <Trash2 className="w-4 h-4" />
                    Delete
                  </>
                )}
              </button>
              <button
                onClick={() => setDeleteConfirmOpen(false)}
                className="flex-1 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 py-2 rounded hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                Cancel
              </button>
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-4 text-center">
              ✓ Deletion will be logged in audit trail
            </p>
          </div>
        </div>
      )}

      {/* Share Modal */}
      <ShareModal
        isOpen={isShareModalOpen}
        onClose={() => setIsShareModalOpen(false)}
        secretId={secretId}
        secretTitle={secretTitle}
      />
    </>
  );
};

export default SecretActions;
