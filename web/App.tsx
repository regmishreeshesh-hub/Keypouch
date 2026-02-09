import React, { useState, useEffect } from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Register from './pages/Register';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import Contacts from './pages/Contacts';
import Secrets from './pages/Secrets';
import AdminDashboard from './pages/AdminDashboard';
import AdminUsers from './pages/AdminUsers';
import AuditLogs from './pages/AuditLogs';
import SharedSecret from './pages/SharedSecret';
import Layout from './components/Layout';
import { register } from './services/authService';
import { ThemeProvider } from './contexts/ThemeContext';

const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const token = localStorage.getItem('token');
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return <Layout>{children}</Layout>;
};

const AdminRoute = ({ children }: { children: React.ReactNode }) => {
  const token = localStorage.getItem('token');
  const role = localStorage.getItem('role');
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  if (role !== 'admin') {
      return <Navigate to="/contacts" replace />;
  }
  return <Layout>{children}</Layout>;
};

const PublicRoute = ({ children }: { children: React.ReactNode }) => {
  const token = localStorage.getItem('token');
  if (token) {
    return <Navigate to="/contacts" replace />;
  }
  return <>{children}</>;
};

const App: React.FC = () => {
  useEffect(() => {
    // Attempt to create the default admin user on startup
    const initDefaultUser = async () => {
      try {
        await register('admin', 'admin', 'What is your favorite color?', 'blue');
        console.log('Default admin user initialized');
      } catch (error: any) {
        // User likely already exists or backend is unreachable, which is fine
        const errorMessage = error?.message || String(error);
        if (errorMessage.includes('Username already exists') || errorMessage.includes('already exists')) {
          console.log('✓ Default admin user already exists');
        } else if (errorMessage.includes('Registration failed') && errorMessage.includes('400')) {
          // 400 error during registration typically means user exists
          console.log('✓ Default admin user already exists (implicit)');
        } else {
          // Only log if it's a real error (not just user exists)
          console.debug('Default admin user setup: ', errorMessage);
        }
      }
    };
    initDefaultUser();
  }, []);

  return (
    <ThemeProvider>
      <HashRouter>
        <Routes>
          <Route path="/login" element={
            <PublicRoute>
              <Login />
            </PublicRoute>
          } />
          <Route path="/register" element={
            <PublicRoute>
              <Register />
            </PublicRoute>
          } />
          <Route path="/forgot-password" element={
            <PublicRoute>
              <ForgotPassword />
            </PublicRoute>
          } />
          <Route path="/reset-password" element={
            <PublicRoute>
              <ResetPassword />
            </PublicRoute>
          } />
          <Route path="/share/:token" element={
              <SharedSecret />
          } />
          <Route path="/contacts" element={
            <ProtectedRoute>
              <Contacts />
            </ProtectedRoute>
          } />
          <Route path="/secrets" element={
            <ProtectedRoute>
              <Secrets />
            </ProtectedRoute>
          } />
          <Route path="/admin" element={
            <AdminRoute>
              <AdminDashboard />
            </AdminRoute>
          } />
          <Route path="/admin/users" element={
            <AdminRoute>
              <AdminUsers />
            </AdminRoute>
          } />
          <Route path="/admin/logs" element={
            <AdminRoute>
              <AuditLogs />
            </AdminRoute>
          } />
          <Route path="/" element={<Navigate to="/contacts" replace />} />
        </Routes>
      </HashRouter>
    </ThemeProvider>
  );
};

export default App;