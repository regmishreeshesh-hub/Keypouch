import React from 'react';
import { EmergencyContact } from '../../types';

interface EmergencyContactsProps {
  contacts: EmergencyContact[];
}

const EmergencyContacts: React.FC<EmergencyContactsProps> = ({ contacts }) => {
  if (!contacts.length) {
    return (
      <div className="text-sm text-gray-500 dark:text-gray-400">No emergency contacts listed.</div>
    );
  }

  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {contacts.map((contact) => (
        <div
          key={contact.id}
          className="rounded-xl border border-amber-200/70 dark:border-amber-700/60 bg-amber-50/70 dark:bg-amber-900/20 p-4"
        >
          <div className="flex items-start justify-between gap-2">
            <div>
              <div className="text-sm font-semibold text-gray-900 dark:text-white">
                {contact.name}
              </div>
              <div className="text-xs text-amber-800 dark:text-amber-200 font-semibold uppercase tracking-wide">
                {contact.relationship}
              </div>
            </div>
            <span className="text-xs font-semibold text-amber-800 dark:text-amber-200 bg-amber-100 dark:bg-amber-900/40 px-2 py-1 rounded-full">
              Emergency
            </span>
          </div>
          <div className="mt-3 space-y-1 text-sm text-gray-700 dark:text-gray-200">
            <div>{contact.phone}</div>
            <div className="text-gray-600 dark:text-gray-300">{contact.email}</div>
          </div>
        </div>
      ))}
    </div>
  );
};

export default EmergencyContacts;
