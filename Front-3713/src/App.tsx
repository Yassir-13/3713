// src/App.tsx
// 🔄 App principal avec route Settings A2F
import React, { useEffect, useState } from 'react';
import './App.css';
import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap-icons/font/bootstrap-icons.css';
import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
import HomePage from './pages/HomePage';
import ScannerPage from './pages/Scanner';
import Login from './pages/Login';
import Register from './pages/Register';
import Settings from './pages/Settings'; // 🆕 AJOUTÉ
import ScanDetailsPage from './pages/ScanDetailsPage';
import ScanHistoryPage from './pages/ScanHistoryPage';

const App: React.FC = () => {

  // Composant pour les routes protégées
  const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
    // Vérifier l'authentification au moment du rendu du composant
    const authenticated = localStorage.getItem("token") !== null;
    
    // Afficher un log pour debug (à retirer plus tard)
    console.log("ProtectedRoute - auth status:", authenticated ? "Authenticated" : "Not authenticated");
    
    if (!authenticated) {
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
        <Route 
          path="/scan-history" 
          element={
            <ProtectedRoute>
              <ScanHistoryPage />
            </ProtectedRoute>
          } 
        />
        {/* 🆕 NOUVELLE ROUTE SETTINGS */}
        <Route 
          path="/settings" 
          element={
            <ProtectedRoute>
              <Settings />
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