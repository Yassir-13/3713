import React, { useContext } from 'react';
import { AuthContext } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';

const Header: React.FC = () => {
  const { darkMode, toggleTheme } = useTheme();
  const { user, logout } = useContext(AuthContext);


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
              <span style={{ color: 'var(--text-color)' }}>Welcome, {user.name}</span>
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
