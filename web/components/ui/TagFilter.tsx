import React from 'react';

type Option = {
  id: string;
  label: string;
  color?: string;
  darkColor?: string;
};

type Props = {
  options: Option[];
  selected?: string;
  onSelect: (id: string) => void;
};

const TagFilter: React.FC<Props> = ({ options, selected, onSelect }) => {
  return (
    <div className="flex flex-wrap gap-2">
      <button
        onClick={() => onSelect('')}
        className={`inline-flex items-center px-3 py-1.5 rounded-full text-sm font-medium transition-colors ${selected === '' ? 'bg-primary-600 text-white shadow-sm' : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700'}`}>
        All
      </button>
      {options.map((o) => (
        <button
          key={o.id}
          onClick={() => onSelect(selected === o.id ? '' : o.id)}
          className={`inline-flex items-center px-3 py-1.5 rounded-full text-sm font-medium transition-colors ${selected === o.id ? 'bg-primary-600 text-white shadow-sm' : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700'}`}>
          {o.label}
        </button>
      ))}
    </div>
  );
};

export default TagFilter;
