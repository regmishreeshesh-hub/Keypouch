import React, { useState } from 'react';
import PasswordGenerator from '../components/PasswordGenerator';

const TestPasswordGen = () => {
    const [selectedPassword, setSelectedPassword] = useState('');

    return (
        <div className="p-10 flex flex-col items-center justify-center min-h-screen bg-gray-100">
            <h1 className="text-2xl mb-4">Password Generator Test</h1>
            <div className="relative">
                <PasswordGenerator
                    onSelectPassword={(pwd) => {
                        console.log('Selected:', pwd);
                        setSelectedPassword(pwd);
                    }}
                    onClose={() => console.log('Closed')}
                />
            </div>
            {selectedPassword && <div className="mt-4">Selected: {selectedPassword}</div>}
        </div>
    );
};

export default TestPasswordGen;
