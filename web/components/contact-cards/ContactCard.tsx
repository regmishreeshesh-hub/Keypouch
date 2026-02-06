import React from 'react';
import { EmployeeContact } from '../../types';
import PhoneList from './PhoneList';
import EmergencyContacts from './EmergencyContacts';

interface ContactCardProps {
  contact: EmployeeContact;
}

const ContactCard: React.FC<ContactCardProps> = ({ contact }) => {
  return (
    <article className="rounded-2xl border border-gray-200 dark:border-gray-700 bg-white/90 dark:bg-gray-800/90 shadow-sm p-6 space-y-5">
      <header className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white">{contact.name}</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400">{contact.role}</p>
          </div>
          <div className="text-sm text-gray-600 dark:text-gray-300">{contact.email}</div>
        </div>
        <div className="text-sm text-gray-600 dark:text-gray-300">
          {contact.address ?? 'Address not provided'}
        </div>
      </header>

      <section className="grid gap-6 lg:grid-cols-[1fr,1.4fr]">
        <div className="rounded-xl bg-gray-50 dark:bg-gray-900/40 border border-gray-200/70 dark:border-gray-700/60 p-4">
          <div className="text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">
            Phone Numbers
          </div>
          <div className="mt-3">
            <PhoneList phones={contact.phones} />
          </div>
        </div>

        <div>
          <div className="text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">
            Emergency Contacts
          </div>
          <div className="mt-3">
            <EmergencyContacts contacts={contact.emergencyContacts} />
          </div>
        </div>
      </section>
    </article>
  );
};

export default ContactCard;
