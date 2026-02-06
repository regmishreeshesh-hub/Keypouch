import React from 'react';
import ContactCard from '../components/contact-cards/ContactCard';
import { EmployeeContact } from '../types';

const sampleContacts: EmployeeContact[] = [
  {
    id: 'c-1001',
    name: 'Avery Bennett',
    email: 'avery.bennett@keypouch.io',
    role: 'Director of Operations',
    address: '742 Evergreen Terrace, Springfield, IL 62704',
    phones: [
      { type: 'work', number: '217-555-0142' },
      { type: 'cell', number: '217-555-0198' }
    ],
    emergencyContacts: [
      {
        id: 2001,
        name: 'Morgan Bennett',
        phone: '217-555-0119',
        email: 'morgan.bennett@email.com',
        relationship: 'spouse'
      },
      {
        id: 2002,
        name: 'Jamie Bennett',
        phone: '217-555-0176',
        email: 'jamie.bennett@email.com',
        relationship: 'parent'
      }
    ]
  },
  {
    id: 'c-1002',
    name: 'Riley Chen',
    email: 'riley.chen@keypouch.io',
    role: 'Security Analyst',
    address: '18 Market Street, San Francisco, CA 94105',
    phones: [
      { type: 'work', number: '415-555-0191' },
      { type: 'home', number: '415-555-0120' },
      { type: 'cell', number: '415-555-0184' }
    ],
    emergencyContacts: [
      {
        id: 2003,
        name: 'Casey Chen',
        phone: '415-555-0135',
        email: 'casey.chen@email.com',
        relationship: 'sibling'
      }
    ]
  },
  {
    id: 'c-1003',
    name: 'Jordan Patel',
    email: 'jordan.patel@keypouch.io',
    role: 'People Ops Manager',
    address: undefined,
    phones: [
      { type: 'work', number: '312-555-0111' },
      { type: 'cell', number: '312-555-0188' }
    ],
    emergencyContacts: [
      {
        id: 2004,
        name: 'Priya Patel',
        phone: '312-555-0167',
        email: 'priya.patel@email.com',
        relationship: 'friend'
      },
      {
        id: 2005,
        name: 'Sam Patel',
        phone: '312-555-0150',
        email: 'sam.patel@email.com',
        relationship: 'other'
      }
    ]
  }
];

const Directory: React.FC = () => {
  return (
    <div className="space-y-8">
      <header className="rounded-2xl bg-gradient-to-br from-slate-900 via-slate-800 to-slate-700 text-white p-8 shadow-lg">
        <div className="max-w-3xl space-y-3">
          <p className="text-sm uppercase tracking-[0.3em] text-slate-300">Employee Directory</p>
          <h1 className="text-3xl sm:text-4xl font-semibold">Contact Profiles & Emergency Contacts</h1>
          <p className="text-sm sm:text-base text-slate-200">
            View complete contact details, labeled phone numbers, and emergency contacts in a single, scannable layout.
          </p>
        </div>
      </header>

      <section className="grid gap-6">
        {sampleContacts.map((contact) => (
          <ContactCard key={contact.id} contact={contact} />
        ))}
      </section>
    </div>
  );
};

export default Directory;
