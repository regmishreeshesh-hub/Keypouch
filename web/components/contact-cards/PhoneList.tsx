import React from 'react';
import { PhoneNumber } from '../../types';

const phoneTypeLabel: Record<PhoneNumber['type'], string> = {
  work: 'Work',
  home: 'Home',
  cell: 'Cell'
};

interface PhoneListProps {
  phones: PhoneNumber[];
}

const PhoneList: React.FC<PhoneListProps> = ({ phones }) => {
  if (!phones.length) {
    return <div className="text-sm text-gray-500 dark:text-gray-400">Not provided</div>;
  }

  return (
    <ul className="space-y-2">
      {phones.map((phone) => (
        <li key={`${phone.type}-${phone.number}`} className="flex items-center justify-between gap-3">
          <span className="text-sm text-gray-700 dark:text-gray-200">{phone.number}</span>
          <span className="text-xs font-semibold uppercase tracking-wide text-primary-700 dark:text-primary-300 bg-primary-50 dark:bg-primary-900/40 px-2 py-1 rounded-full">
            {phoneTypeLabel[phone.type]}
          </span>
        </li>
      ))}
    </ul>
  );
};

export default PhoneList;
