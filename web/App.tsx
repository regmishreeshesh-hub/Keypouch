import React from 'react';
import { HashRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import Login from './pages/Login';
import Register from './pages/Register';
import AdminSetup from './pages/AdminSetup';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import ChangePassword from './pages/ChangePassword';
import Contacts from './pages/Contacts';
import Secrets from './pages/Secrets';
import AdminUsers from './pages/AdminUsers';
import AuditLogs from './pages/AuditLogs';
import SharedSecret from './pages/SharedSecret';
import Layout from './components/Layout';
import { ThemeProvider } from './contexts/ThemeContext';

const ProtectedRoute = ({ children }: { children: React.ReactElement }) => {
  const token = localStorage.getItem('token');
  const mustReset = localStorage.getItem('must_reset_password') === 'true';
  const location = useLocation();
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  if (mustReset && location.pathname !== '/change-password') {
    return <Navigate to="/change-password" replace />;
  }
  return <Layout>{children}</Layout>;
};

const AdminRoute = ({ children }: { children: React.ReactElement }) => {
  const token = localStorage.getItem('token');
  const role = localStorage.getItem('role');
  const mustReset = localStorage.getItem('must_reset_password') === 'true';
  const location = useLocation();
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  if (mustReset && location.pathname !== '/change-password') {
    return <Navigate to="/change-password" replace />;
  }
  if (role !== 'admin') {
      return <Navigate to="/contacts" replace />;
  }
  return <Layout>{children}</Layout>;
};

const PublicRoute = ({ children }: { children: React.ReactElement }) => {
  const token = localStorage.getItem('token');
  if (token) {
    return <Navigate to="/contacts" replace />;
  }
  return children;
};

const App: React.FC = () => {
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
          <Route path="/admin-setup" element={
            <PublicRoute>
              <AdminSetup />
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
          <Route path="/change-password" element={
            <ProtectedRoute>
              <ChangePassword />
            </ProtectedRoute>
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
