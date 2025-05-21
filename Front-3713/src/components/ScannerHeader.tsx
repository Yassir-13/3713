// src/components/layout/Header.tsx

import React from 'react';
import { useTheme } from '../context/ThemeContext';

const ScannerHeader: React.FC = () => {
    const { darkMode, toggleTheme } = useTheme();
    

    return (
        <nav className="navbar navbar-expand-lg navbar-dark bg-dark px-4 justify-content-between fixed-top w-100">
          <div className="d-flex align-items-center gap-2" >
            <i className="bi bi-shield-lock fs-4 text-success"></i>
            <a className="navbar-brand mb-0 h4" href="/">3713</a>
          </div>
    
          <div className="text-light">
            <span className="me-2">Welcome</span>
            <span className="fw-bold text-success">Again</span>
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
