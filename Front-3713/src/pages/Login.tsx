// src/pages/Login.tsx - VERSION CORRIGÉE
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
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [twoFactorError, setTwoFactorError] = useState('');
  const [requiresTwoFactor, setRequiresTwoFactor] = useState(false);
  const [pendingUserId, setPendingUserId] = useState<number | null>(null);

  const { login, isAuthenticated } = useContext(AuthContext);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/scanner');
    }
  }, [isAuthenticated, navigate]);

  // 🔧 CORRECTION : Sauvegarder aussi le refresh_token
  const performLogin = async (email: string, password: string, twoFactorCode?: string) => {
    console.log('🔧 DEBUG: Performing login', { 
      email, 
      hasTwoFactorCode: !!twoFactorCode 
    });

    try {
      const response = await axios.post('http://localhost:8000/api/auth/login', {
        email,
        password,
        ...(twoFactorCode && { two_factor_code: twoFactorCode })
      });

      console.log('🔧 DEBUG: Login response:', response.data);

      const data = response.data;

      // Si 2FA requis
      if (data.requires_2fa === true && data.user_id) {
        console.log('🔧 DEBUG: 2FA required for user:', data.user_id);
        setRequiresTwoFactor(true);
        setPendingUserId(data.user_id);
        return false;
      }

      // Login réussi
      if (data.user && data.access_token) {
        console.log('🔧 DEBUG: Login successful, calling context login');
        
        // 🔧 CORRECTION CRITIQUE : Sauvegarder le refresh_token
        if (data.refresh_token) {
          localStorage.setItem('refresh_token', data.refresh_token);
          console.log('🔧 DEBUG: Refresh token saved');
        }
        
        login(data.user, data.access_token);
        
        const state = location.state as LocationState;
        const redirectPath = state?.from?.pathname || '/scanner';
        navigate(redirectPath);
        return true;
      } else {
        throw new Error('Invalid server response');
      }
      
    } catch (err: any) {
      console.log('🔧 DEBUG: Login error:', err);
      
      if (err.response?.data?.message) {
        throw new Error(err.response.data.message);
      } else {
        throw new Error('Login failed');
      }
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setTwoFactorError('');
    setLoading(true);

    try {
      await performLogin(email, password);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleTwoFactorSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setTwoFactorError('');
    
    if (!twoFactorCode.trim()) {
      setTwoFactorError('Please enter your 2FA code');
      return;
    }

    setLoading(true);

    try {
      const success = await performLogin(email, password, twoFactorCode.trim());
      if (success) {
        console.log('🔧 DEBUG: 2FA login successful');
      }
    } catch (err: any) {
      console.log('🔧 DEBUG: 2FA error:', err.message);
      setTwoFactorError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCancelTwoFactor = () => {
    setRequiresTwoFactor(false);
    setPendingUserId(null);
    setTwoFactorCode('');
    setTwoFactorError('');
  };

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
        <h2 className="text-center mb-4">
          {requiresTwoFactor ? 'Two-Factor Authentication' : 'Login'}
        </h2>

        {requiresTwoFactor && (
          <div className="mb-3 text-center" style={{ fontSize: "0.9rem", opacity: 0.8 }}>
            Step 2 of 2: Enter your authentication code
          </div>
        )}

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

        {!requiresTwoFactor ? (
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
          <form onSubmit={handleTwoFactorSubmit}>
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