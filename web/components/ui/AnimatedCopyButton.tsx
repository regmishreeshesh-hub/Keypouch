import React, { useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Copy, Check } from 'lucide-react';

type Props = {
  value?: string;
  title?: string;
  showText?: boolean;
};

const AnimatedCopyButton: React.FC<Props> = ({ value, title, showText = true }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    if (!value) {
      console.warn('No value to copy');
      return;
    }
    
    try {
      // Try modern clipboard API first
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
        console.log('Copied to clipboard (API):', value);
      } else {
        // Fallback to older method
        const textArea = document.createElement('textarea');
        textArea.value = value;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        const successful = document.execCommand('copy');
        if (successful) {
          console.log('Copied to clipboard (fallback):', value);
        } else {
          throw new Error('execCommand failed');
        }
        
        document.body.removeChild(textArea);
      }
      
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
    }
  }, [value]);

  return (
    <motion.div className="relative inline-flex items-center gap-2">
      <button
        type="button"
        onClick={handleCopy}
        className="inline-flex items-center justify-center p-2 rounded-md transition-colors duration-200 cursor-pointer hover:bg-gray-200 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 flex-shrink-0 z-10"
        title={title || 'Copy to clipboard'}
        aria-label="Copy to clipboard"
      >
        <motion.span 
          initial={{ opacity: 1 }} 
          animate={{ opacity: copied ? 0 : 1 }}
          transition={{ duration: 0.2 }}
          className="inline-flex"
        >
          <Copy className="w-4 h-4 text-gray-600 dark:text-gray-300" />
        </motion.span>
        <motion.span 
          initial={{ opacity: 0, scale: 0.8 }} 
          animate={{ opacity: copied ? 1 : 0, scale: copied ? 1 : 0.8 }} 
          transition={{ duration: 0.2 }}
          className="absolute inline-flex"
        >
          <Check className="w-4 h-4 text-green-500" />
        </motion.span>
      </button>
      {showText && (
        <motion.span
          initial={{ opacity: 0, x: -10 }}
          animate={{ opacity: copied ? 1 : 0, x: copied ? 0 : -10 }}
          transition={{ duration: 0.2 }}
          className="text-xs text-green-600 dark:text-green-400 font-medium whitespace-nowrap"
        >
          Copied!
        </motion.span>
      )}
    </motion.div>
  );
};

export default AnimatedCopyButton;
