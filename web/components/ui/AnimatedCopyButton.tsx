import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Copy, Check } from 'lucide-react';

type Props = {
  value?: string;
  title?: string;
};

const AnimatedCopyButton: React.FC<Props> = ({ value, title }) => {
  const [copied, setCopied] = useState(false);

  const doCopy = async () => {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch (e) {
      console.error('copy failed', e);
    }
  };

  return (
    <motion.button
      onClick={doCopy}
      whileTap={{ scale: 0.95 }}
      className="inline-flex items-center justify-center p-2 rounded-md"
      title={title || 'Copy'}
    >
      <motion.span initial={{ opacity: 1 }} animate={{ opacity: copied ? 0 : 1 }}>
        <Copy className="w-4 h-4 text-gray-400 hover:text-primary-600" />
      </motion.span>
      <motion.span initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: copied ? 1 : 0, scale: copied ? 1 : 0.8 }} className="absolute">
        <Check className="w-4 h-4 text-green-500" />
      </motion.span>
    </motion.button>
  );
};

export default AnimatedCopyButton;
