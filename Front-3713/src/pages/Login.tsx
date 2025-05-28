// src/pages/Login.tsx - Version Finale Corrigée
import React, { useState, useContext, useEffect } from 'react';
import axios from 'axios';
import { AuthContext } from '../context/AuthContext';
import { useNavigate, useLocation } from 'react-router-dom';
import '../App.css';

interface LocationState {
  from?: {
    pathname: string;
  };
}

const Login: React.FC = () => {
  // Local states
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [twoFactorError, setTwoFactorError] = useState('');

  // Context and navigation - GARDE LA MÊME LOGIQUE QUI FONCTIONNE
  const { 
    login, 
    isAuthenticated, 
    twoFactorRequired, 
    setTwoFactorRequired, 
    submitTwoFactor, 
    clearTwoFactor,
    pendingUserId  // CRITIQUE : Garder cette ligne !
  } = useContext(AuthContext);
  
  const navigate = useNavigate();
  const location = useLocation();

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/scanner');
    }
  }, [isAuthenticated, navigate]);

  // Main login form submission - GARDE LA MÊME LOGIQUE
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setTwoFactorError('');
    setLoading(true);

    try {
      const response = await axios.post('http://localhost:8000/api/login', {
        email,
        password,
      });

      const data = response.data;

      // Check if 2FA is required
      if (data.requires_2fa === true && data.user_id) {
        setTwoFactorRequired(true, data.user_id, { email, password });
        setLoading(false);
        return;
      }

      // Normal login successful
      if (data.user && data.token) {
        login(data.user, data.token);
        
        const state = location.state as LocationState;
        const redirectPath = state?.from?.pathname || '/scanner';
        navigate(redirectPath);
      } else {
        setError('Invalid server response');
      }
      
    } catch (err: any) {
      if (err.response?.data?.message) {
        setError(err.response.data.message);
      } else {
        setError('Invalid credentials or server error');
      }
    } finally {
      setLoading(false);
    }
  };

  // Two-factor authentication form submission - GARDE LA MÊME LOGIQUE
  const handleTwoFactorSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setTwoFactorError('');
    
    if (!twoFactorCode.trim()) {
      setTwoFactorError('Please enter your 2FA code');
      return;
    }

    setLoading(true);

    try {
      await submitTwoFactor(twoFactorCode.trim());
      
      const state = location.state as LocationState;
      const redirectPath = state?.from?.pathname || '/scanner';
      navigate(redirectPath);
      
    } catch (err: any) {
      setTwoFactorError(err.message || 'Invalid 2FA code');
    } finally {
      setLoading(false);
    }
  };

  // Cancel two-factor authentication - GARDE LA MÊME LOGIQUE
  const handleCancelTwoFactor = () => {
    clearTwoFactor();
    setTwoFactorCode('');
    setTwoFactorError('');
  };

  // Simple 2FA code validation - GARDE LA MÊME LOGIQUE
  const isValidTwoFactorCode = (code: string) => {
    const cleanCode = code.replace(/\s/g, '');
    return /^\d{6}$/.test(cleanCode) || /^[A-Z0-9]{8}$/i.test(cleanCode);
  };

  return (
    <div
      className="d-flex justify-content-center align-items-center vh-100"
      style={{ backgroundColor: 'var(--bg-color)' }}
    >
      <div
        style={{
          marginTop: "2rem",
          padding: "1.5rem",
          border: "1px solid var(--accent-color)",
          borderRadius: "8px",
          boxShadow: "0 0 12px var(--accent-color)",
          backgroundColor:'var(--bg-color)',
          color: "var(--text-color)",
          maxWidth: "500px",
          minWidth: "400px",
        }}
      >
        {/* Dynamic title */}
        <h2 className="text-center mb-4">
          {twoFactorRequired ? 'Two-Factor Authentication' : 'Login'}
        </h2>

        {/* Progress indicator for 2FA */}
        {twoFactorRequired && (
          <div className="mb-3 text-center" style={{ fontSize: "0.9rem", opacity: 0.8 }}>
            Step 2 of 2: Enter your authentication code
          </div>
        )}

        {/* Error messages */}
        {error && (
          <div className="alert alert-danger text-center mb-3">
            {error}
          </div>
        )}
        {twoFactorError && (
          <div className="alert alert-danger text-center mb-3">
            {twoFactorError}
          </div>
        )}

        {/* Conditional rendering based on twoFactorRequired */}
        {!twoFactorRequired ? (
          /* ========== NORMAL LOGIN FORM ========== */
          <form onSubmit={handleSubmit}>
            <div className="mb-3">
              <label className="form-label">Email:</label>
              <input
                type="email"
                className="form-control"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={loading}
              />
            </div>

            <div className="mb-3">
              <label className="form-label">Password:</label>
              <input
                type="password"
                className="form-control"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={loading}
              />
            </div>

            <button  
              type="submit"
              className="btn w-100"
              style={{
                backgroundColor: 'var(--border-color)',
                color: 'var(--bg-color)',
                border: '1px solid var(--border-color)',
              }}
              disabled={loading}
            >
              {loading ? 'Logging in...' : 'Log in'}
            </button>
          </form>
        ) : (
          /* ========== TWO-FACTOR AUTHENTICATION FORM ========== */
          <form onSubmit={handleTwoFactorSubmit}>
            {/* User info */}
            <div className="mb-3 p-2 text-center" style={{ 
              backgroundColor: "rgba(0,0,0,0.1)", 
              borderRadius: "4px" 
            }}>
              Logging in as: <strong>{email}</strong>
            </div>

            <div className="mb-3">
              <label className="form-label">Authentication Code:</label>
              <input
                type="text"
                className="form-control"
                value={twoFactorCode}
                onChange={(e) => setTwoFactorCode(e.target.value.toUpperCase())} 
                placeholder="6-digit code or 8-character recovery code"
                maxLength={8}
                required
                disabled={loading}
                autoFocus
                style={{
                  fontFamily: 'monospace',
                  fontSize: '1.1rem',
                  letterSpacing: '0.1em',
                  textAlign: 'center',
                }}
              />
              
              <div className="mt-2 text-center" style={{ fontSize: "0.8rem", opacity: 0.7 }}>
                Enter the code from your authenticator app
              </div>
            </div>

            {/* 2FA buttons */}
            <div className="d-flex gap-2">
              <button  
                type="submit"
                className="btn flex-grow-1"
                style={{
                  backgroundColor: 'var(--border-color)',
                  color: 'var(--bg-color)',
                  border: '1px solid var(--border-color)',
                }}
                disabled={loading || !isValidTwoFactorCode(twoFactorCode)}
              >
                {loading ? 'Verifying...' : 'Verify Code'}
              </button>
              
              <button  
                type="button"
                onClick={handleCancelTwoFactor}
                className="btn"
                style={{
                  backgroundColor: 'transparent',
                  color: 'var(--text-color)',
                  border: '1px solid var(--border-color)',
                }}
                disabled={loading}
              >
                Back
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};

export default Login;