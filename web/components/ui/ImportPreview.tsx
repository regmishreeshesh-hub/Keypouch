import React from 'react';
import { ContactPayload } from '../../types';
import { X, Check } from 'lucide-react';

type Props = {
  rows: ContactPayload[];
  onCancel: () => void;
  onConfirm: (rows: ContactPayload[]) => void;
};

const ImportPreview: React.FC<Props> = ({ rows, onCancel, onConfirm }) => {
  return (
    <div className="space-y-4">
      <div className="text-sm text-gray-600 dark:text-gray-400">Preview the first 10 rows parsed from your file. Confirm to complete the import.</div>
      <div className="overflow-auto max-h-64 border rounded bg-white dark:bg-gray-800 p-2">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-gray-500 uppercase">
              <th className="px-2 py-1">Name</th>
              <th className="px-2 py-1">Phone</th>
              <th className="px-2 py-1">Address</th>
              <th className="px-2 py-1">Emergency</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 50).map((r, idx) => (
              <tr key={idx} className="border-b border-gray-100 dark:border-gray-700">
                <td className="px-2 py-1">{r.name}</td>
                <td className="px-2 py-1">{r.phone}</td>
                <td className="px-2 py-1 truncate">{r.address}</td>
                <td className="px-2 py-1">
                  {r.emergencyContacts && r.emergencyContacts.length > 0 ? (
                    <span className="text-xs text-gray-600 dark:text-gray-300">{r.emergencyContacts.length} contact(s)</span>
                  ) : (
                    <span className="text-xs text-gray-400">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex justify-end gap-3">
        <button onClick={onCancel} className="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md bg-white dark:bg-gray-700 text-sm text-gray-700 dark:text-gray-200"> 
          <X className="w-4 h-4 mr-2" /> Cancel
        </button>
        <button onClick={() => onConfirm(rows)} className="inline-flex items-center px-4 py-2 bg-primary-600 text-white rounded-md"> 
          <Check className="w-4 h-4 mr-2" /> Confirm Import
        </button>
      </div>
    </div>
  );
};

export default ImportPreview;
