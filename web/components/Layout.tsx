import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { LogOut, Phone, Shield, User as UserIcon, Sun, Moon, Users, Activity, AlertCircle } from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';
import Modal from './Modal';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const username = localStorage.getItem('username');
  const role = localStorage.getItem('role');
  const { theme, toggleTheme } = useTheme();
  
  const [isLogoutModalOpen, setIsLogoutModalOpen] = useState(false);

  const handleLogoutClick = () => {
    setIsLogoutModalOpen(true);
  };

  const confirmLogout = () => {
    // Only remove auth items, preserve database (db_*) and theme
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    localStorage.removeItem('role');
    localStorage.removeItem('must_reset_password');
    localStorage.removeItem('is_demo');
    setIsLogoutModalOpen(false);
    navigate('/login');
  };

  const isActive = (path: string) => location.pathname === path;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors duration-200 flex flex-col">
      <nav className="bg-white dark:bg-gray-800 shadow-sm z-10 transition-colors duration-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex">
              <div className="flex-shrink-0 flex items-center gap-2">
                <div className="bg-primary-600 p-1.5 rounded-lg">
                  <Shield className="h-6 w-6 text-white" />
                </div>
                <span className="font-bold text-xl text-gray-900 dark:text-white">KeyPouch</span>
              </div>
              <div className="hidden sm:ml-8 sm:flex sm:space-x-8">
                <button
                  onClick={() => navigate('/contacts')}
                  className={`${
                    isActive('/contacts')
                      ? 'border-primary-500 text-gray-900 dark:text-white'
                      : 'border-transparent text-gray-500 dark:text-gray-300 hover:border-gray-300 hover:text-gray-700 dark:hover:text-gray-100'
                  } inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium transition-colors duration-200`}
                >
                  <Phone className="w-4 h-4 mr-2" />
                  Contacts
                </button>
                <button
                  onClick={() => navigate('/secrets')}
                  className={`${
                    isActive('/secrets')
                      ? 'border-primary-500 text-gray-900 dark:text-white'
                      : 'border-transparent text-gray-500 dark:text-gray-300 hover:border-gray-300 hover:text-gray-700 dark:hover:text-gray-100'
                  } inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium transition-colors duration-200`}
                >
                  <Shield className="w-4 h-4 mr-2" />
                  Secrets
                </button>
                {role === 'admin' && (
                  <>
                    <button
                      onClick={() => navigate('/admin/users')}
                      className={`${
                        isActive('/admin/users')
                          ? 'border-primary-500 text-gray-900 dark:text-white'
                          : 'border-transparent text-gray-500 dark:text-gray-300 hover:border-gray-300 hover:text-gray-700 dark:hover:text-gray-100'
                      } inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium transition-colors duration-200`}
                    >
                      <Users className="w-4 h-4 mr-2" />
                      Users
                    </button>
                    <button
                      onClick={() => navigate('/admin/logs')}
                      className={`${
                        isActive('/admin/logs')
                          ? 'border-primary-500 text-gray-900 dark:text-white'
                          : 'border-transparent text-gray-500 dark:text-gray-300 hover:border-gray-300 hover:text-gray-700 dark:hover:text-gray-100'
                      } inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium transition-colors duration-200`}
                    >
                      <Activity className="w-4 h-4 mr-2" />
                      Audit Logs
                    </button>
                  </>
                )}
              </div>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={toggleTheme}
                className="p-2 rounded-full text-gray-500 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                aria-label="Toggle Dark Mode"
              >
                {theme === 'light' ? <Moon className="w-5 h-5" /> : <Sun className="w-5 h-5" />}
              </button>

              <div className="hidden md:flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 px-3 py-1 rounded-full">
                <UserIcon className="w-4 h-4" />
                {username}
                {role === 'admin' && <span className="text-xs bg-primary-600 text-white px-1.5 py-0.5 rounded ml-1">Admin</span>}
              </div>
              <button
                onClick={handleLogoutClick}
                className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/40 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 transition-colors duration-200"
              >
                <LogOut className="w-4 h-4 sm:mr-2" />
                <span className="hidden sm:inline">Logout</span>
              </button>
            </div>
          </div>
        </div>
        
        {/* Mobile Navigation */}
        <div className="sm:hidden border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 flex justify-around p-2">
           <button
              onClick={() => navigate('/contacts')}
              className={`flex flex-col items-center p-2 rounded-md ${isActive('/contacts') ? 'text-primary-600 bg-white dark:bg-gray-700 shadow-sm' : 'text-gray-500 dark:text-gray-400'}`}
           >
             <Phone className="w-5 h-5" />
             <span className="text-xs mt-1">Contacts</span>
           </button>
           <button
              onClick={() => navigate('/secrets')}
              className={`flex flex-col items-center p-2 rounded-md ${isActive('/secrets') ? 'text-primary-600 bg-white dark:bg-gray-700 shadow-sm' : 'text-gray-500 dark:text-gray-400'}`}
           >
             <Shield className="w-5 h-5" />
             <span className="text-xs mt-1">Secrets</span>
           </button>
           {role === 'admin' && (
             <>
                <button
                    onClick={() => navigate('/admin/users')}
                    className={`flex flex-col items-center p-2 rounded-md ${isActive('/admin/users') ? 'text-primary-600 bg-white dark:bg-gray-700 shadow-sm' : 'text-gray-500 dark:text-gray-400'}`}
                >
                <Users className="w-5 h-5" />
                <span className="text-xs mt-1">Users</span>
                </button>
                <button
                    onClick={() => navigate('/admin/logs')}
                    className={`flex flex-col items-center p-2 rounded-md ${isActive('/admin/logs') ? 'text-primary-600 bg-white dark:bg-gray-700 shadow-sm' : 'text-gray-500 dark:text-gray-400'}`}
                >
                <Activity className="w-5 h-5" />
                <span className="text-xs mt-1">Logs</span>
                </button>
             </>
           )}
        </div>
      </nav>

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 text-gray-900 dark:text-white">
        {children}
      </main>

      {/* Logout Confirmation Modal */}
      <Modal 
        isOpen={isLogoutModalOpen} 
        onClose={() => setIsLogoutModalOpen(false)} 
        title="Confirm Logout"
      >
        <div className="text-center">
           <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100 dark:bg-red-900/30 mb-4">
              <LogOut className="h-6 w-6 text-red-600 dark:text-red-400" />
           </div>
           <h3 className="text-lg font-medium text-gray-900 dark:text-white">Ready to leave?</h3>
           <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
             Are you sure you want to log out of your account?
           </p>
           <div className="mt-6 flex justify-center gap-3">
             <button
               onClick={() => setIsLogoutModalOpen(false)}
               className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
             >
               Cancel
             </button>
             <button
               onClick={confirmLogout}
               className="px-4 py-2 border border-transparent rounded-md text-sm font-medium text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
             >
               Logout
             </button>
           </div>
        </div>
      </Modal>
    </div>
  );
};

export default Layout;
