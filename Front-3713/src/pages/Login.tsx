// src/pages/Login.tsx - VERSION ULTRA-SÉCURISÉE
import React, { useState, useContext, useEffect } from 'react';
import axios from 'axios';
import { AuthContext } from '../context/AuthContext';
import { useNavigate, useLocation } from 'react-router-dom';
import secureValidator from '../utils/secureInputValidation';
import '../App.css';

interface LocationState {
  from?: {
    pathname: string;
  };
}

const Login: React.FC = () => {
  // États du formulaire
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    twoFactorCode: ''
  });
  
  // États de validation
  const [fieldErrors, setFieldErrors] = useState<Record<string, string[]>>({});
  const [globalError, setGlobalError] = useState('');
  const [loading, setLoading] = useState(false);
  
  // États 2FA
  const [requiresTwoFactor, setRequiresTwoFactor] = useState(false);
  const [pendingUserId, setPendingUserId] = useState<number | null>(null);
  
  // États de sécurité
  const [attemptCount, setAttemptCount] = useState(0);
  const [isBlocked, setIsBlocked] = useState(false);
  const [blockTimeRemaining, setBlockTimeRemaining] = useState(0);

  const { login, isAuthenticated } = useContext(AuthContext);
  const navigate = useNavigate();
  const location = useLocation();

  // 🔒 Protection contre le brute force côté client
  useEffect(() => {
    const storedAttempts = localStorage.getItem('loginAttempts');
    const lastAttempt = localStorage.getItem('lastLoginAttempt');
    
    if (storedAttempts && lastAttempt) {
      const attempts = parseInt(storedAttempts);
      const timeSinceLastAttempt = Date.now() - parseInt(lastAttempt);
      const blockDuration = Math.min(attempts * 30000, 300000); // Max 5 minutes
      
      if (attempts >= 5 && timeSinceLastAttempt < blockDuration) {
        setIsBlocked(true);
        setAttemptCount(attempts);
        setBlockTimeRemaining(Math.ceil((blockDuration - timeSinceLastAttempt) / 1000));
        
        const timer = setInterval(() => {
          setBlockTimeRemaining(prev => {
            if (prev <= 1) {
              setIsBlocked(false);
              clearInterval(timer);
              return 0;
            }
            return prev - 1;
          });
        }, 1000);
        
        return () => clearInterval(timer);
      } else if (timeSinceLastAttempt > blockDuration) {
        // Reset si le temps de blocage est écoulé
        localStorage.removeItem('loginAttempts');
        localStorage.removeItem('lastLoginAttempt');
      }
    }
  }, []);

  // Redirection si déjà authentifié
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/scanner');
    }
  }, [isAuthenticated, navigate]);

  /**
   * 🔒 Gestion sécurisée des changements de champs
   */
  const handleSecureInputChange = (field: string, value: string) => {
    // Validation temps réel pour UX
    let fieldValidation: any;
    
    switch (field) {
      case 'email':
        fieldValidation = secureValidator.validateEmail(value);
        break;
      case 'password':
        fieldValidation = secureValidator.validatePassword(value);
        break;
      case 'twoFactorCode':
        fieldValidation = secureValidator.validateTwoFactorCode(value);
        break;
      default:
        fieldValidation = { isValid: true, sanitized: value, errors: [] };
    }

    // Mise à jour du state avec valeur sanitisée
    setFormData(prev => ({
      ...prev,
      [field]: field === 'password' ? value : fieldValidation.sanitized || value
    }));

    // Mise à jour des erreurs de validation
    setFieldErrors(prev => ({
      ...prev,
      [field]: fieldValidation.errors
    }));

    // Clear global error quand l'utilisateur tape
    if (globalError) {
      setGlobalError('');
    }
  };

  /**
   * 🔒 Gestion sécurisée de la soumission
   */
  const handleSecureSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (isBlocked) {
      setGlobalError(`Too many failed attempts. Please wait ${blockTimeRemaining} seconds.`);
      return;
    }

    setGlobalError('');
    setLoading(true);

    // Validation complète du formulaire
    const validation = secureValidator.validateLoginForm({
      email: formData.email,
      password: formData.password,
      two_factor_code: formData.twoFactorCode
    });
    
    if (!validation.isValid) {
      // Extraire seulement les erreurs de chaque champ
      const extractedErrors: Record<string, string[]> = {};
      for (const [field, result] of Object.entries(validation.fieldResults)) {
        extractedErrors[field] = result.errors;
      }
      setFieldErrors(extractedErrors);
      setGlobalError('Please fix the validation errors above');
      setLoading(false);
      return;
    }

    try {
      // 🔒 Détection d'injection avancée
      const inputValues = Object.values(validation.sanitizedData).join(' ');
      if (secureValidator.detectAdvancedInjection(inputValues)) {
        throw new Error('Invalid input detected');
      }

      // 🔒 Headers sécurisés
      const secureHeaders = secureValidator.validateHeaders({
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-API-Version': 'v1.0'
      });

      console.log('🔒 Submitting secure login with validated data');

      const response = await axios.post('http://localhost:8000/api/auth/login', 
        validation.sanitizedData,
        { 
          headers: secureHeaders,
          timeout: 30000 // 30s timeout
        }
      );

      console.log('🔒 Login response received:', response.status);

      const data = response.data;

      // Gestion de la réponse 2FA
      if (data.requires_2fa === true && data.user_id) {
        console.log('🔒 2FA required for user:', data.user_id);
        setRequiresTwoFactor(true);
        setPendingUserId(data.user_id);
        
        // Reset attempts counter pour 2FA
        localStorage.removeItem('loginAttempts');
        localStorage.removeItem('lastLoginAttempt');
        
        setLoading(false);
        return;
      }

      // Login réussi
      if (data.user && data.access_token) {
        console.log('🔒 Login successful, processing authentication');
        
        // Sauvegarde du refresh token
        if (data.refresh_token) {
          localStorage.setItem('refresh_token', data.refresh_token);
        }
        
        // Reset compteurs d'échec
        localStorage.removeItem('loginAttempts');
        localStorage.removeItem('lastLoginAttempt');
        
        login(data.user, data.access_token);
        
        const state = location.state as LocationState;
        const redirectPath = state?.from?.pathname || '/scanner';
        navigate(redirectPath);
      } else {
        throw new Error('Invalid server response format');
      }
      
    } catch (err: any) {
      console.error('🔒 Login error:', err);
      
      // 🔒 Gestion sécurisée des erreurs
      handleLoginError(err);
    } finally {
      setLoading(false);
    }
  };

  /**
   * 🔒 Gestion sécurisée des erreurs de login
   */
  const handleLoginError = (error: any) => {
    // Incrémenter compteur d'échecs
    const currentAttempts = parseInt(localStorage.getItem('loginAttempts') || '0') + 1;
    localStorage.setItem('loginAttempts', currentAttempts.toString());
    localStorage.setItem('lastLoginAttempt', Date.now().toString());
    
    setAttemptCount(currentAttempts);

    // Blocage progressif
    if (currentAttempts >= 5) {
      const blockDuration = Math.min(currentAttempts * 30, 300); // Max 5 minutes
      setIsBlocked(true);
      setBlockTimeRemaining(blockDuration);
      
      const timer = setInterval(() => {
        setBlockTimeRemaining(prev => {
          if (prev <= 1) {
            setIsBlocked(false);
            clearInterval(timer);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }

    // Message d'erreur approprié
    if (error.response?.status === 429) {
      setGlobalError('Too many login attempts. Please wait before trying again.');
    } else if (error.response?.status === 422) {
      if (error.response.data?.message?.includes('2FA')) {
        setGlobalError('Invalid 2FA code. Please try again.');
      } else {
        setGlobalError('Invalid input format. Please check your entries.');
      }
    } else if (error.response?.status === 401) {
      setGlobalError('Invalid email or password.');
    } else if (error.message === 'Invalid input detected') {
      setGlobalError('Invalid characters detected in input.');
    } else {
      setGlobalError('Login failed. Please try again.');
    }
  };

  /**
   * 🔒 Annulation sécurisée du 2FA
   */
  const handleCancelTwoFactor = () => {
    setRequiresTwoFactor(false);
    setPendingUserId(null);
    setFormData(prev => ({ ...prev, twoFactorCode: '' }));
    setFieldErrors({});
    setGlobalError('');
  };

  /**
   * 🔒 Validation du code 2FA
   */
  const isValidTwoFactorCode = (code: string) => {
    const cleanCode = code.replace(/\s/g, '');
    return /^\d{6}$/.test(cleanCode) || /^[A-Z0-9]{8}$/i.test(cleanCode);
  };

  return (
    <div
      className="d-flex justify-content-center align-items-center vh-100"
      style={{ backgroundColor: 'var(--bg-color)' }}
    >
      <div style={styles.container}>
        
        {/* En-tête */}
        <h2 className="text-center mb-4" style={styles.title}>
          {requiresTwoFactor ? 'Two-Factor Authentication' : 'Login'}
        </h2>


        {/* Indicateur 2FA */}
        {requiresTwoFactor && (
          <div style={styles.twoFactorIndicator}>
            Step 2 of 2: Enter your authentication code
          </div>
        )}

        {/* Erreur globale */}
        {globalError && (
          <div style={styles.errorAlert}>
            {globalError}
          </div>
        )}

        {/* Indicateur de blocage */}
        {isBlocked && (
          <div style={styles.blockAlert}>
            Account temporarily locked due to multiple failed attempts.
            <br />Time remaining: {Math.floor(blockTimeRemaining / 60)}m {blockTimeRemaining % 60}s
          </div>
        )}

        {/* Formulaire */}
        <form onSubmit={handleSecureSubmit}>
          
          {!requiresTwoFactor ? (
            <>
              {/* Email */}
              <div style={styles.inputGroup}>
                <label style={styles.label}>Email:</label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => handleSecureInputChange('email', e.target.value)}
                  style={{
                    ...styles.input,
                    ...(fieldErrors.email?.length > 0 ? styles.inputError : {})
                  }}
                  required
                  disabled={loading || isBlocked}
                  autoComplete="email"
                  maxLength={100}
                />
                {fieldErrors.email?.map((error, index) => (
                  <div key={index} style={styles.fieldError}>{error}</div>
                ))}
              </div>

              {/* Password */}
              <div style={styles.inputGroup}>
                <label style={styles.label}>Password:</label>
                <input
                  type="password"
                  value={formData.password}
                  onChange={(e) => handleSecureInputChange('password', e.target.value)}
                  style={{
                    ...styles.input,
                    ...(fieldErrors.password?.length > 0 ? styles.inputError : {})
                  }}
                  required
                  disabled={loading || isBlocked}
                  autoComplete="current-password"
                  maxLength={255}
                />
                {fieldErrors.password?.map((error, index) => (
                  <div key={index} style={styles.fieldError}>{error}</div>
                ))}
              </div>
            </>
          ) : (
            <>
              {/* User info pour 2FA */}
              <div style={styles.userInfo}>
                Logging in as: <strong>{formData.email}</strong>
              </div>

              {/* Code 2FA */}
              <div style={styles.inputGroup}>
                <label style={styles.label}>Authentication Code:</label>
                <input
                  type="text"
                  value={formData.twoFactorCode}
                  onChange={(e) => handleSecureInputChange('twoFactorCode', e.target.value.toUpperCase())}
                  style={{
                    ...styles.input,
                    ...styles.codeInput,
                    ...(fieldErrors.twoFactorCode?.length > 0 ? styles.inputError : {})
                  }}
                  placeholder="000000"
                  maxLength={8}
                  required
                  disabled={loading}
                  autoFocus
                  autoComplete="one-time-code"
                />
                {fieldErrors.twoFactorCode?.map((error, index) => (
                  <div key={index} style={styles.fieldError}>{error}</div>
                ))}
                
                <div style={styles.inputHint}>
                  Enter the 6-digit code from your authenticator app or 8-character recovery code
                </div>
              </div>
            </>
          )}

          {/* Actions */}
          <div style={styles.actions}>
            {!requiresTwoFactor ? (
              <button
                type="submit"
                style={{
                  ...styles.primaryButton,
                  ...(isBlocked ? styles.disabledButton : {})
                }}
                disabled={loading || isBlocked}
              >
                {loading ? 'Logging in...' : 'Log in'}
              </button>
            ) : (
              <div style={styles.twoFactorActions}>
                <button
                  type="submit"
                  style={{
                    ...styles.primaryButton,
                    flex: 1
                  }}
                  disabled={loading || !isValidTwoFactorCode(formData.twoFactorCode)}
                >
                  {loading ? 'Verifying...' : 'Verify Code'}
                </button>
                
                <button
                  type="button"
                  onClick={handleCancelTwoFactor}
                  style={{
                    ...styles.secondaryButton,
                    flex: 1
                  }}
                  disabled={loading}
                >
                  Back
                </button>
              </div>
            )}
          </div>

          {/* Informations de sécurité */}
          <div style={styles.securityInfo}>
            {attemptCount > 0 && !isBlocked && (
              <div style={styles.warningText}>
                ⚠️ {attemptCount} failed attempt{attemptCount > 1 ? 's' : ''}. 
                Account will be locked after 5 attempts.
              </div>
            )}
          </div>
        </form>

        {/* Lien vers l'inscription */}
        <div className="text-center mt-3">
          <p>Don't have an account? <a href="/register" style={{ color: 'var(--accent-color)' }}>Register here</a></p>
        </div>
      </div>
    </div>
  );
};

// Styles sécurisés
const styles = {
  container: {
    marginTop: "2rem",
    padding: "2rem",
    border: "2px solid var(--accent-color)",
    borderRadius: "12px",
    boxShadow: "0 0 20px var(--accent-color)",
    backgroundColor: 'var(--bg-color)',
    color: "var(--text-color)",
    maxWidth: "500px",
    minWidth: "400px",
  },
  title: {
    color: "var(--text-color)",
    fontWeight: "bold"
  },
  securityIndicator: {
    textAlign: "center" as const,
    fontSize: "0.8rem",
    color: "#2ecc71",
    marginBottom: "1rem",
    padding: "0.5rem",
    backgroundColor: "rgba(46, 204, 113, 0.1)",
    borderRadius: "4px",
    border: "1px solid rgba(46, 204, 113, 0.3)"
  },
  twoFactorIndicator: {
    textAlign: "center" as const,
    fontSize: "0.9rem",
    opacity: 0.8,
    marginBottom: "1rem"
  },
  userInfo: {
    textAlign: "center" as const,
    padding: "0.75rem",
    backgroundColor: "rgba(0,0,0,0.1)",
    borderRadius: "4px",
    marginBottom: "1rem"
  },
  inputGroup: {
    marginBottom: "1rem"
  },
  label: {
    display: "block",
    marginBottom: "0.5rem",
    fontWeight: "bold"
  },
  input: {
    width: "100%",
    padding: "0.75rem",
    border: "2px solid var(--accent-color)",
    borderRadius: "6px",
    backgroundColor: "rgba(255, 255, 255, 0.05)",
    color: "var(--text-color)",
    fontSize: "1rem",
    transition: "border-color 0.3s ease",
    boxSizing: "border-box" as const
  },
  inputError: {
    borderColor: "#e74c3c",
    backgroundColor: "rgba(231, 76, 60, 0.05)"
  },
  codeInput: {
    textAlign: "center" as const,
    fontSize: "1.5rem",
    fontFamily: "monospace",
    letterSpacing: "0.2em"
  },
  fieldError: {
    color: "#e74c3c",
    fontSize: "0.8rem",
    marginTop: "0.25rem"
  },
  inputHint: {
    fontSize: "0.8rem",
    opacity: 0.7,
    textAlign: "center" as const,
    marginTop: "0.5rem"
  },
  errorAlert: {
    backgroundColor: "rgba(231, 76, 60, 0.1)",
    border: "1px solid #e74c3c",
    borderRadius: "4px",
    padding: "0.75rem",
    color: "#e74c3c",
    marginBottom: "1rem",
    textAlign: "center" as const
  },
  blockAlert: {
    backgroundColor: "rgba(255, 193, 7, 0.1)",
    border: "1px solid #ffc107",
    borderRadius: "4px",
    padding: "0.75rem",
    color: "#ffc107",
    marginBottom: "1rem",
    textAlign: "center" as const,
    fontWeight: "bold"
  },
  actions: {
    marginTop: "1.5rem"
  },
  twoFactorActions: {
    display: "flex",
    gap: "0.75rem"
  },
  primaryButton: {
    width: "100%",
    padding: "0.75rem 1.5rem",
    backgroundColor: "var(--border-color)",
    color: "var(--bg-color)",
    border: "none",
    borderRadius: "6px",
    fontSize: "1rem",
    fontWeight: "bold",
    cursor: "pointer",
    transition: "transform 0.2s ease"
  },
  secondaryButton: {
    padding: "0.75rem 1.5rem",
    backgroundColor: "transparent",
    color: "var(--text-color)",
    border: "2px solid var(--border-color)",
    borderRadius: "6px",
    fontSize: "1rem",
    cursor: "pointer"
  },
  disabledButton: {
    backgroundColor: "#666",
    cursor: "not-allowed"
  },
  securityInfo: {
    marginTop: "1rem",
    padding: "0.75rem",
    backgroundColor: "rgba(0, 0, 0, 0.1)",
    borderRadius: "4px"
  },
  warningText: {
    color: "#f39c12",
    fontSize: "0.85rem",
    marginBottom: "0.5rem",
    textAlign: "center" as const
  },
  infoText: {
    fontSize: "0.8rem",
    opacity: 0.7,
    textAlign: "center" as const,
    lineHeight: 1.4
  }
};

export default Login;