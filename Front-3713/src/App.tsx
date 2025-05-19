// src/App.tsx
import React, { useEffect } from 'react';
import './App.css';
import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap-icons/font/bootstrap-icons.css';
import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
import HomePage from './pages/HomePage';
import ScannerPage from './pages/Scanner';
import Login from './pages/Login';
import Register from './pages/Register';
import ScanDetailsPage from './pages/ScanDetailsPage';
import ScanHistory from './pages/ScanHistory';

const App: React.FC = () => {
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
      document.body.classList.add('dark-mode');
    } else {
      document.body.classList.remove('dark-mode');
    }
  }, []);

  // Vérifie si l'utilisateur est connecté
  const isAuthenticated = () => {
    return localStorage.getItem("token") !== null;
  };

  // Composant pour les routes protégées
  const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
    if (!isAuthenticated()) {
      return <Navigate to="/login" replace />;
    }
    return <>{children}</>;
  };

  return (
    <Router>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route 
          path="/scanner" 
          element={
            <ProtectedRoute>
              <ScannerPage />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/scan/:scanId" 
          element={
            <ProtectedRoute>
              <ScanDetailsPage />
            </ProtectedRoute>
          } 
        />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        {/* Redirection vers la page d'accueil pour les routes inconnues */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
};

export default App;