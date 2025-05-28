// src/components/Sidebar.tsx - Version avec Settings A2F
import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

const Sidebar: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation(); // Pour suivre la route active
  
  // Fonction pour gérer la déconnexion
  const handleLogout = () => {
    // Supprimer le token d'authentification
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    // Rediriger vers la page de connexion
    navigate('/login');
  };

  // Fonction de navigation sécurisée
  const navigateTo = (path: string) => (e: React.MouseEvent) => {
    e.preventDefault(); // Empêcher le comportement par défaut
    console.log(`Navigating to: ${path}`);
    navigate(path);
  };

  // Fonction pour vérifier si un lien est actif
  const isActive = (path: string) => {
    return location.pathname === path;
  };

  return (
    <div
      className="bg-dark text-white d-flex flex-column justify-content-between position-fixed"
      style={{
        top: '56px',
        left: 0,
        width: '250px',
        height: 'calc(100vh - 56px)',
        zIndex: 1020,
      }}
    >
      <div>
        <div className="p-3 border-bottom border-secondary">
          <div className="fw-bold mb-1">Cyber Security Analyst</div>
          <div className="text-muted small">mail@gmail.com</div>
        </div>
        <ul className="nav flex-column p-3">
          <li className="nav-item mb-2">
            <a 
              className={`nav-link text-white ${isActive('/scanner') ? 'bg-success rounded' : ''}`}
              onClick={navigateTo('/scanner')}
              style={{ cursor: 'pointer' }}
            >
              <i className="bi bi-search me-2"></i> New Scan
            </a>
          </li>
          <li className="nav-item mb-2">
            <a 
              className={`nav-link text-white ${isActive('/scan-history') ? 'bg-success rounded' : ''}`}
              onClick={navigateTo('/scan-history')}
              style={{ cursor: 'pointer' }}
            >
              <i className="bi bi-clock-history me-2"></i> Scan History
            </a>
          </li>
          <li className="nav-item mb-2">
            <a 
              className={`nav-link text-white ${isActive('/reports') ? 'bg-success rounded' : ''}`}
              onClick={navigateTo('/reports')}
              style={{ cursor: 'pointer' }}
            >
              <i className="bi bi-bar-chart me-2"></i> Reports
            </a>
          </li>
          
          {/* 🆕 NOUVEAU LIEN SETTINGS */}
          <li className="nav-item mb-2">
            <a 
              className={`nav-link text-white ${isActive('/settings') ? 'bg-success rounded' : ''}`}
              onClick={navigateTo('/settings')}
              style={{ cursor: 'pointer' }}
            >
              <i className="bi bi-gear me-2"></i> Settings
            </a>
          </li>
        </ul>
      </div>
      <div className="p-3 border-top border-secondary">
        <a 
          className="nav-link text-danger"
          onClick={handleLogout}
          style={{ cursor: 'pointer' }}
        >
          <i className="bi bi-box-arrow-right me-2"></i> Logout
        </a>
      </div>
    </div>
  );
};

export default Sidebar;