// src/pages/Register.tsx - VERSION ULTRA-SÉCURISÉE
import React, { useState, useContext, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';
import secureValidator from '../utils/secureInputValidation';

const Register: React.FC = () => {
  // États du formulaire
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    password_confirmation: ''
  });
  
  // États de validation
  const [fieldErrors, setFieldErrors] = useState<Record<string, string[]>>({});
  const [globalError, setGlobalError] = useState('');
  const [loading, setLoading] = useState(false);
  
  // États de sécurité
  const [attemptCount, setAttemptCount] = useState(0);
  const [isBlocked, setIsBlocked] = useState(false);
  const [blockTimeRemaining, setBlockTimeRemaining] = useState(0);
  const [passwordStrength, setPasswordStrength] = useState('');

  const { login, isAuthenticated } = useContext(AuthContext);
  const navigate = useNavigate();

  // 🔒 Protection contre le brute force côté client
  useEffect(() => {
    const storedAttempts = localStorage.getItem('registerAttempts');
    const lastAttempt = localStorage.getItem('lastRegisterAttempt');
    
    if (storedAttempts && lastAttempt) {
      const attempts = parseInt(storedAttempts);
      const timeSinceLastAttempt = Date.now() - parseInt(lastAttempt);
      const blockDuration = Math.min(attempts * 45000, 600000); // Max 10 minutes pour registration
      
      if (attempts >= 3 && timeSinceLastAttempt < blockDuration) {
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
        localStorage.removeItem('registerAttempts');
        localStorage.removeItem('lastRegisterAttempt');
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
   * 🔒 Évaluation de la force du mot de passe
   */
  const evaluatePasswordStrength = (password: string): string => {
    if (!password) return '';
    
    let score = 0;
    const feedback = [];

    // Longueur
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    
    // Complexité
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^a-zA-Z0-9]/.test(password)) score += 1;

    // Patterns communs (réduire le score)
    if (/123|abc|password|qwerty/i.test(password)) score -= 2;
    if (/(.)\1{2,}/.test(password)) score -= 1;

    if (score <= 2) return 'weak';
    if (score <= 4) return 'medium';
    if (score <= 5) return 'strong';
    return 'very-strong';
  };

  /**
   * 🔒 Gestion sécurisée des changements de champs
   */
  const handleSecureInputChange = (field: string, value: string) => {
    // Validation temps réel pour UX
    let fieldValidation: any;
    
    switch (field) {
      case 'name':
        fieldValidation = secureValidator.validateName(value);
        break;
      case 'email':
        fieldValidation = secureValidator.validateEmail(value);
        break;
      case 'password':
        fieldValidation = secureValidator.validatePassword(value);
        // Évaluer la force du mot de passe
        setPasswordStrength(evaluatePasswordStrength(value));
        break;
      case 'password_confirmation':
        fieldValidation = secureValidator.validatePassword(value);
        // Vérifier la correspondance avec le mot de passe
        if (value && formData.password && value !== formData.password) {
          fieldValidation.errors.push('Passwords do not match');
          fieldValidation.isValid = false;
        }
        break;
      default:
        fieldValidation = { isValid: true, sanitized: value, errors: [] };
    }

    // Mise à jour du state avec valeur sanitisée
    setFormData(prev => ({
      ...prev,
      [field]: ['password', 'password_confirmation'].includes(field) ? value : fieldValidation.sanitized || value
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
      setGlobalError(`Too many registration attempts. Please wait ${Math.floor(blockTimeRemaining / 60)}m ${blockTimeRemaining % 60}s.`);
      return;
    }

    setGlobalError('');
    setLoading(true);

    // Validation complète du formulaire
    const validation = secureValidator.validateRegistrationForm(formData);
    
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

      // 🔒 Headers sécurisés (compatibles CORS)
      const secureHeaders = secureValidator.validateHeaders({
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-API-Version': 'v1.0'
      });

      console.log('🔒 Submitting secure registration with validated data');

      const response = await axios.post('http://localhost:8000/api/auth/register', 
        validation.sanitizedData,
        { 
          headers: secureHeaders,
          timeout: 30000 // 30s timeout
        }
      );

      console.log('🔒 Registration response received:', response.status);

      const data = response.data;

      // Registration réussie
      if (data.user && data.access_token) {
        console.log('🔒 Registration successful, processing authentication');
        
        // Sauvegarde du refresh token
        if (data.refresh_token) {
          localStorage.setItem('refresh_token', data.refresh_token);
        }
        
        // Reset compteurs d'échec
        localStorage.removeItem('registerAttempts');
        localStorage.removeItem('lastRegisterAttempt');
        
        login(data.user, data.access_token);
        navigate('/scanner');
      } else {
        throw new Error('Invalid server response format');
      }
      
    } catch (err: any) {
      console.error('🔒 Registration error:', err);
      
      // 🔒 Gestion sécurisée des erreurs
      handleRegistrationError(err);
    } finally {
      setLoading(false);
    }
  };

  /**
   * 🔒 Gestion sécurisée des erreurs de registration
   */
  const handleRegistrationError = (error: any) => {
    // Incrémenter compteur d'échecs
    const currentAttempts = parseInt(localStorage.getItem('registerAttempts') || '0') + 1;
    localStorage.setItem('registerAttempts', currentAttempts.toString());
    localStorage.setItem('lastRegisterAttempt', Date.now().toString());
    
    setAttemptCount(currentAttempts);

    // Blocage progressif (plus strict pour registration)
    if (currentAttempts >= 3) {
      const blockDuration = Math.min(currentAttempts * 45, 600); // Max 10 minutes
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
      setGlobalError('Too many registration attempts. Please wait before trying again.');
    } else if (error.response?.status === 422) {
      if (error.response.data?.errors) {
        // Erreurs de validation spécifiques du serveur
        const serverErrors = error.response.data.errors;
        const extractedErrors: Record<string, string[]> = {};
        
        for (const [field, messages] of Object.entries(serverErrors)) {
          extractedErrors[field] = Array.isArray(messages) ? messages : [messages as string];
        }
        
        setFieldErrors(prev => ({
          ...prev,
          ...extractedErrors
        }));
        setGlobalError('Please fix the validation errors above');
      } else {
        setGlobalError('Invalid input format. Please check your entries.');
      }
    } else if (error.response?.status === 409) {
      setGlobalError('An account with this email already exists.');
    } else if (error.message === 'Invalid input detected') {
      setGlobalError('Invalid characters detected in input.');
    } else {
      setGlobalError('Registration failed. Please try again.');
    }
  };

  /**
   * 🔒 Obtenir la couleur de la force du mot de passe
   */
  const getPasswordStrengthColor = () => {
    switch (passwordStrength) {
      case 'weak': return '#e74c3c';
      case 'medium': return '#f39c12';
      case 'strong': return '#2ecc71';
      case 'very-strong': return '#27ae60';
      default: return '#bdc3c7';
    }
  };

  /**
   * 🔒 Obtenir le texte de la force du mot de passe
   */
  const getPasswordStrengthText = () => {
    switch (passwordStrength) {
      case 'weak': return '🔴 Weak';
      case 'medium': return '🟡 Medium';
      case 'strong': return '🟢 Strong';
      case 'very-strong': return '💚 Very Strong';
      default: return '';
    }
  };

  // Vérifier si le formulaire peut être soumis
  const canSubmit = () => {
    return !loading && 
           !isBlocked && 
           formData.name.trim() && 
           formData.email.trim() && 
           formData.password.trim() && 
           formData.password_confirmation.trim() &&
           formData.password === formData.password_confirmation &&
           Object.values(fieldErrors).every(errors => errors.length === 0);
  };

  return (
    <div
      className="d-flex justify-content-center align-items-center vh-100"
      style={{ backgroundColor: 'var(--bg-color)' }}
    >
      <div style={styles.container}>
        
        {/* En-tête */}
        <h2 className="text-center mb-4" style={styles.title}>
          Registration
        </h2>

        {/* Erreur globale */}
        {globalError && (
          <div style={styles.errorAlert}>
            {globalError}
          </div>
        )}

        {/* Indicateur de blocage */}
        {isBlocked && (
          <div style={styles.blockAlert}>
            Registration temporarily blocked due to multiple failed attempts.
            <br />Time remaining: {Math.floor(blockTimeRemaining / 60)}m {blockTimeRemaining % 60}s
          </div>
        )}

        {/* Formulaire */}
        <form onSubmit={handleSecureSubmit}>
          
          {/* Nom */}
          <div style={styles.inputGroup}>
            <label style={styles.label}>Full Name:</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => handleSecureInputChange('name', e.target.value)}
              style={{
                ...styles.input,
                ...(fieldErrors.name?.length > 0 ? styles.inputError : {})
              }}
              required
              disabled={loading || isBlocked}
              autoComplete="name"
              maxLength={50}
              placeholder="Enter your full name"
            />
            {fieldErrors.name?.map((error, index) => (
              <div key={index} style={styles.fieldError}>{error}</div>
            ))}
          </div>

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
              placeholder="Enter your email address"
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
              autoComplete="new-password"
              maxLength={255}
              placeholder="Create a strong password"
            />
            {fieldErrors.password?.map((error, index) => (
              <div key={index} style={styles.fieldError}>{error}</div>
            ))}
            
            {/* Indicateur de force du mot de passe */}
            {formData.password && (
              <div style={styles.passwordStrength}>
                <div style={styles.strengthIndicator}>
                  <span style={{ color: getPasswordStrengthColor() }}>
                    {getPasswordStrengthText()}
                  </span>
                </div>
                <div style={styles.strengthBar}>
                  <div 
                    style={{
                      ...styles.strengthFill,
                      width: passwordStrength === 'weak' ? '25%' : 
                             passwordStrength === 'medium' ? '50%' :
                             passwordStrength === 'strong' ? '75%' :
                             passwordStrength === 'very-strong' ? '100%' : '0%',
                      backgroundColor: getPasswordStrengthColor()
                    }}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Confirm Password */}
          <div style={styles.inputGroup}>
            <label style={styles.label}>Confirm Password:</label>
            <input
              type="password"
              value={formData.password_confirmation}
              onChange={(e) => handleSecureInputChange('password_confirmation', e.target.value)}
              style={{
                ...styles.input,
                ...(fieldErrors.password_confirmation?.length > 0 ? styles.inputError : {})
              }}
              required
              disabled={loading || isBlocked}
              autoComplete="new-password"
              maxLength={255}
              placeholder="Confirm your password"
            />
            {fieldErrors.password_confirmation?.map((error, index) => (
              <div key={index} style={styles.fieldError}>{error}</div>
            ))}
            
            {/* Indicateur de correspondance */}
            {formData.password_confirmation && (
              <div style={styles.passwordMatch}>
                {formData.password === formData.password_confirmation ? (
                  <span style={{ color: '#2ecc71' }}>✓ Passwords match</span>
                ) : (
                  <span style={{ color: '#e74c3c' }}>✗ Passwords do not match</span>
                )}
              </div>
            )}
          </div>

          {/* Actions */}
          <div style={styles.actions}>
            <button
              type="submit"
              style={{
                ...styles.primaryButton,
                ...(!canSubmit() ? styles.disabledButton : {})
              }}
              disabled={!canSubmit()}
            >
              {loading ? 'Creating Account...' : 'Create Account'}
            </button>
          </div>

          {/* Informations de sécurité */}
          <div style={styles.securityInfo}>
            {attemptCount > 0 && !isBlocked && (
              <div style={styles.warningText}>
                ⚠️ {attemptCount} failed attempt{attemptCount > 1 ? 's' : ''}. 
                Registration will be blocked after 3 attempts.
              </div>
            )}

          </div>
        </form>

        {/* Lien vers le login */}
        <div className="text-center mt-3">
          <p>Already have an account? <a href="/login" style={{ color: 'var(--accent-color)' }}>Login here</a></p>
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
  fieldError: {
    color: "#e74c3c",
    fontSize: "0.8rem",
    marginTop: "0.25rem"
  },
  passwordStrength: {
    marginTop: "0.5rem"
  },
  strengthIndicator: {
    fontSize: "0.8rem",
    marginBottom: "0.25rem"
  },
  strengthBar: {
    width: "100%",
    height: "4px",
    backgroundColor: "rgba(255, 255, 255, 0.2)",
    borderRadius: "2px",
    overflow: "hidden"
  },
  strengthFill: {
    height: "100%",
    transition: "width 0.3s ease, background-color 0.3s ease"
  },
  passwordMatch: {
    fontSize: "0.8rem",
    marginTop: "0.25rem"
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

export default Register;