import React from 'react';
import { useNavigate } from 'react-router-dom';

const Sidebar: React.FC = () => {
  const navigate = useNavigate();
  
  // Fonction pour gérer la déconnexion
  const handleLogout = () => {
    // Ici, ajoutez votre logique de déconnexion
    // Par exemple, supprimer le token d'authentification du localStorage
    localStorage.removeItem('authToken');
    // Rediriger vers la page de connexion
    navigate('/login');
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
              className="nav-link text-white active bg-success rounded"
              onClick={() => navigate('/scanner')}
              style={{ cursor: 'pointer' }}
            >
              <i className="bi bi-search me-2"></i> New Scan
            </a>
          </li>
          <li className="nav-item mb-2">
            <a 
              className="nav-link text-white" 
              onClick={() => navigate('/scanHistory')}
              style={{ cursor: 'pointer' }}
            >
              <i className="bi bi-clock-history me-2"></i> Scan History
            </a>
          </li>
          <li className="nav-item mb-2">
            <a 
              className="nav-link text-white"
              onClick={() => navigate('/reports')}
              style={{ cursor: 'pointer' }}
            >
              <i className="bi bi-bar-chart me-2"></i> Reports
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