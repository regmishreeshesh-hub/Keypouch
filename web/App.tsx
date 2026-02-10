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
import AdminSetup from './pages/AdminSetup';
import Welcome from './pages/Welcome';
import Layout from './components/Layout';
import { ThemeProvider } from './contexts/ThemeContext';
import DemoSetup from './pages/DemoSetup';
import PasswordRecovery from './pages/PasswordRecovery';

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

const DemoProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const token = localStorage.getItem('token');
  const isDemo = localStorage.getItem('is_demo') === 'true';
  if (!token || !isDemo) {
    return <Navigate to="/login" replace />;
  }
  return <Layout>{children}</Layout>;
};

const App: React.FC = () => {
  useEffect(() => {
    // Remove demo admin user after real admin setup
    const removeDemoAdmin = async () => {
      if (localStorage.getItem('role') === 'admin' && localStorage.getItem('username') !== 'admin') {
        // Call backend to delete demo admin user
        try {
          await fetch('/api/admin/remove-demo', { method: 'POST', headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` } });
          console.log('Demo admin user removed');
        } catch (err) {
          console.debug('Demo admin removal failed:', err);
        }
      }
    };
    removeDemoAdmin();
  }, []);

  // Check if any admin or demo user exists
  const hasAdminOrDemo = Boolean(localStorage.getItem('role'));

  return (
    <ThemeProvider>
      <HashRouter>
        <Routes>
          <Route path="/welcome" element={<Welcome />} />
          <Route path="/enterprise-setup" element={<Navigate to="/admin-setup" replace />} />
          <Route path="/demo-setup" element={<DemoSetup />} />
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
          <Route path="/admin-setup" element={
            <PublicRoute>
              <AdminSetup />
            </PublicRoute>
          } />
          <Route path="/admin/logs" element={
            <AdminRoute>
              <AuditLogs />
            </AdminRoute>
          } />
          <Route path="/password-recovery" element={<PasswordRecovery />} />

          {/* Example: Demo-only route (add your demo pages here) */}
          {/* <Route path="/demo-feature" element={
            <DemoProtectedRoute>
              <DemoFeaturePage />
            </DemoProtectedRoute>
          } /> */}

          {/* Example: Enterprise-only route (already protected by AdminRoute/ProtectedRoute) */}
          {/* <Route path="/enterprise-feature" element={
            <AdminRoute>
              <EnterpriseFeaturePage />
            </AdminRoute>
          } /> */}

          <Route path="/" element={<Navigate to={hasAdminOrDemo ? "/contacts" : "/welcome"} replace />} />
        </Routes>
      </HashRouter>
    </ThemeProvider>
  );
};

export default App;
