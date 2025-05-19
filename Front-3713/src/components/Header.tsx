import React, { useState, useEffect, useContext } from 'react';
import { AuthContext } from '../context/AuthContext';

const Header: React.FC = () => {
  const [darkMode, setDarkMode] = useState(false);
  const { user, logout } = useContext(AuthContext);

useEffect(() => {
  const savedTheme = localStorage.getItem('theme');
  if (savedTheme === 'dark') {
    setDarkMode(true);
  }
}, []);

  const toggleTheme = () => {
    const newTheme = !darkMode;
    setDarkMode(newTheme);
    document.body.classList.toggle('dark-mode');
    localStorage.setItem('theme', newTheme ? 'dark' : 'light');
  };

  return (
    <nav
      className="navbar navbar-expand-lg navbar-light"
      style={{
        background: 'rgba(0, 0, 0, 0.3)',
        backdropFilter: 'blur(10px)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.2)',
      }}
    >
      <div className="container-fluid">
        <a className="navbar-brand" href="/">
          <img src="./public/3713-removebg-preview.png" alt="Logo" style={{ width: '150px', height: 'auto' }} />
        </a>

        <div className="d-flex align-items-center gap-3">
          {!user ? (
            <>
              <a href="/register" className="btn" style={{ backgroundColor: 'var(--border-color)', color: 'var(--bg-color)' }}>Register</a>
              <a href="/login" className="btn" style={{ backgroundColor: 'var(--border-color)', color: 'var(--bg-color)' }}>Login</a>
            </>
          ) : (
            <>
              <span style={{ color: 'var(--text-color)' }}>Bienvenue, {user.name}</span>
              <button onClick={logout} className="btn btn-danger">Logout</button>
            </>
          )}

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
      </div>
    </nav>
  );
};

export default Header;
