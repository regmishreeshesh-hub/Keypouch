import React from 'react';
import { motion } from 'framer-motion';

type Props = {
  title: string;
  subtitle?: string;
  icon?: React.ReactNode;
  children?: React.ReactNode;
  onView?: () => void;
  footer?: React.ReactNode;
};

const ItemCard: React.FC<Props> = ({ title, subtitle, icon, children, onView, footer }) => {
  return (
    <motion.div whileHover={{ y: -3 }} className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg hover:shadow-md transition-shadow duration-200 border border-gray-100 dark:border-gray-700 flex flex-col">
      <div className="p-5 flex-1">
        <div className="flex items-center">
          <div className="flex-shrink-0">{icon}</div>
          <div className="ml-4 w-0 flex-1">
            <div className="text-lg font-medium text-gray-900 dark:text-white truncate">{title}</div>
            {subtitle && <div className="text-sm text-gray-500 dark:text-gray-400 truncate">{subtitle}</div>}
          </div>
        </div>
        {children}
      </div>
      {footer && <div className="bg-gray-50 dark:bg-gray-900/50 px-5 py-3 border-t border-gray-100 dark:border-gray-700 flex justify-between items-center">{footer}</div>}
    </motion.div>
  );
};

export default ItemCard;
