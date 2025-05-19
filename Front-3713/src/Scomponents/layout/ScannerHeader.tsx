// src/components/layout/Header.tsx

import React, { useState, useEffect } from 'react';

const ScannerHeader: React.FC = () => {
    const [darkMode, setDarkMode] = useState(false);
    
      // Charger le thème au démarrage
      useEffect(() => {
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'dark') {
          setDarkMode(true);
          document.body.classList.add('dark-mode');
        }
      }, []);
    
      const toggleTheme = () => {
        const newTheme = !darkMode;
        setDarkMode(newTheme);
        document.body.classList.toggle('dark-mode');
        localStorage.setItem('theme', newTheme ? 'dark' : 'light');
      };

    return (
        <nav className="navbar navbar-expand-lg navbar-dark bg-dark px-4 justify-content-between fixed-top w-100">
          <div className="d-flex align-items-center gap-2" >
            <i className="bi bi-shield-lock fs-4 text-success"></i>
            <a className="navbar-brand mb-0 h4" href="/">3713</a>
          </div>
    
          <div className="text-light">
            <span className="me-2">Welcome,</span>
            <span className="fw-bold text-success">Cyber Security Analyst</span>
          </div>
    
          <div className="d-flex align-items-center gap-3">
            <i className="bi bi-bell-fill text-light"></i>
            <i className="bi bi-person-circle text-light fs-4"></i>
            <button
            onClick={toggleTheme}
            className="btn"
            style={{
              fontSize: '1.5rem',
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              color: 'var(--text-color)',
            }}
          >
            {darkMode ? '🌙' : '☀️'}
          </button>
          </div>
        </nav>
  );
};

export default ScannerHeader;
