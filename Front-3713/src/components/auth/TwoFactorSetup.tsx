// src/components/auth/TwoFactorSetup.tsx
// 🧙‍♂️ Wizard de configuration A2F
import React, { useState } from 'react';
import { useTwoFactor } from '../../hooks/useTwoFactor';
import QRCodeDisplay from '../auth/QRCodeDisplay';
import RecoveryCodesModal from '../auth/RecoveryCodesModal';
import { TwoFactorSetupProps } from '../../types/twoFactor';

const TwoFactorSetup: React.FC<TwoFactorSetupProps> = ({ onComplete, onCancel }) => {
  const {
    setupData,
    currentStep,
    isLoading,
    error,
    generateSecret,
    confirmSetup,
    resetError,
    setStep
  } = useTwoFactor();

  // États locaux
  const [password, setPassword] = useState('');
  const [confirmationCode, setConfirmationCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [showRecoveryModal, setShowRecoveryModal] = useState(false);

  // Étape 1 : Vérification mot de passe
  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!password.trim()) {
      return;
    }

    try {
      await generateSecret(password);
    } catch (err) {
      // Erreur gérée par le hook
    }
  };

  // Étape 2 : Passer à la confirmation
  const handleQRCodeNext = () => {
    setStep('code_confirmation');
  };

  // Étape 3 : Confirmation du code
  const handleConfirmationSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!confirmationCode.trim() || confirmationCode.length !== 6) {
      return;
    }

    try {
      const codes = await confirmSetup(confirmationCode);
      setRecoveryCodes(codes);
      setShowRecoveryModal(true);
    } catch (err) {
      // Erreur gérée par le hook
    }
  };

  // Validation du code de confirmation
  const isValidConfirmationCode = confirmationCode.length === 6 && /^\d{6}$/.test(confirmationCode);

  // Gérer la fermeture des codes de récupération
  const handleRecoveryCodesClose = () => {
    setShowRecoveryModal(false);
    onComplete();
  };

  // Gérer l'annulation
  const handleCancel = () => {
    resetError();
    onCancel();
  };

  return (
    <div style={styles.container}>
      {/* En-tête */}
      <div style={styles.header}>
        <h3 style={styles.title}>Enable Two-Factor Authentication</h3>
        
        {/* Indicateur de progression */}
        <div style={styles.progressContainer}>
          <div style={styles.progressBar}>
            <div 
              style={{
                ...styles.progressFill,
                width: currentStep === 'password_verification' ? '33%' : 
                       currentStep === 'qr_code_display' ? '66%' : '100%'
              }}
            />
          </div>
          <p style={styles.progressText}>
            Step {currentStep === 'password_verification' ? '1' : 
                  currentStep === 'qr_code_display' ? '2' : '3'} of 3
          </p>
        </div>
      </div>

      {/* Erreur globale */}
      {error && (
        <div style={styles.error}>
          <strong>Error:</strong> {error}
          <button onClick={resetError} style={styles.closeButton}>×</button>
        </div>
      )}

      {/* Contenu selon l'étape */}
      <div style={styles.content}>
        
        {/* ÉTAPE 1 : Vérification mot de passe */}
        {currentStep === 'password_verification' && (
          <div style={styles.step}>
            <div style={styles.stepHeader}>
              <h4 style={styles.stepTitle}>🔐 Verify Your Password</h4>
              <p style={styles.stepDescription}>
                Please enter your current password to continue setting up two-factor authentication.
              </p>
            </div>
            
            <form onSubmit={handlePasswordSubmit} style={styles.form}>
              <div style={styles.inputGroup}>
                <label style={styles.label}>Current Password:</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  style={styles.input}
                  placeholder="Enter your current password"
                  required
                  disabled={isLoading}
                  autoFocus
                />
              </div>
              
              <div style={styles.formActions}>
                <button
                  type="button"
                  onClick={handleCancel}
                  style={styles.cancelButton}
                  disabled={isLoading}
                >
                  Cancel
                </button>
                
                <button
                  type="submit"
                  style={styles.primaryButton}
                  disabled={isLoading || !password.trim()}
                >
                  {isLoading ? 'Verifying...' : 'Continue'}
                </button>
              </div>
            </form>
          </div>
        )}

        {/* ÉTAPE 2 : QR Code */}
        {currentStep === 'qr_code_display' && setupData && (
          <QRCodeDisplay
            qrCode={setupData.qr_code}
            secret={setupData.secret}
            onNext={handleQRCodeNext}
          />
        )}

        {/* ÉTAPE 3 : Confirmation code */}
        {currentStep === 'code_confirmation' && (
          <div style={styles.step}>
            <div style={styles.stepHeader}>
              <h4 style={styles.stepTitle}>📱 Verify Setup</h4>
              <p style={styles.stepDescription}>
                Enter the 6-digit code from your authenticator app to complete the setup.
              </p>
            </div>
            
            <form onSubmit={handleConfirmationSubmit} style={styles.form}>
              <div style={styles.inputGroup}>
                <label style={styles.label}>Authentication Code:</label>
                <input
                  type="text"
                  value={confirmationCode}
                  onChange={(e) => setConfirmationCode(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
                  style={{
                    ...styles.input,
                    ...styles.codeInput
                  }}
                  placeholder="000000"
                  maxLength={6}
                  required
                  disabled={isLoading}
                  autoFocus
                />
                
                <div style={styles.inputHint}>
                  Enter the 6-digit code shown in your authenticator app
                </div>
              </div>
              
              <div style={styles.formActions}>
                <button
                  type="button"
                  onClick={() => setStep('qr_code_display')}
                  style={styles.backButton}
                  disabled={isLoading}
                >
                  Back
                </button>
                
                <button
                  type="submit"
                  style={styles.primaryButton}
                  disabled={isLoading || !isValidConfirmationCode}
                >
                  {isLoading ? 'Verifying...' : 'Enable 2FA'}
                </button>
              </div>
            </form>
          </div>
        )}

        {/* États d'erreur ou de chargement */}
        {currentStep === 'error' && (
          <div style={styles.step}>
            <div style={styles.errorState}>
              <span style={styles.errorIcon}>❌</span>
              <h4>Setup Failed</h4>
              <p>There was an error setting up two-factor authentication.</p>
              <button onClick={handleCancel} style={styles.primaryButton}>
                Try Again
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Modal codes de récupération */}
      <RecoveryCodesModal
        isOpen={showRecoveryModal}
        codes={recoveryCodes}
        onClose={handleRecoveryCodesClose}
        onDownload={() => {
          // Téléchargement géré par le modal
        }}
      />
    </div>
  );
};

const styles = {
  container: {
    backgroundColor: 'rgba(255, 255, 255, 0.03)',
    border: '2px solid var(--accent-color)',
    borderRadius: '12px',
    padding: '2rem',
    maxWidth: '600px',
    margin: '0 auto',
    boxShadow: '0 0 20px rgba(0, 0, 0, 0.3)',
  },
  header: {
    textAlign: 'center' as const,
    marginBottom: '2rem',
  },
  title: {
    fontSize: '1.5rem',
    fontWeight: 'bold',
    color: 'var(--text-color)',
    marginBottom: '1rem',
  },
  progressContainer: {
    marginBottom: '1rem',
  },
  progressBar: {
    width: '100%',
    height: '6px',
    backgroundColor: 'rgba(255, 255, 255, 0.1)',
    borderRadius: '3px',
    overflow: 'hidden',
    marginBottom: '0.5rem',
  },
  progressFill: {
    height: '100%',
    backgroundColor: 'var(--accent-color)',
    transition: 'width 0.3s ease',
  },
  progressText: {
    fontSize: '0.85rem',
    opacity: 0.7,
    margin: 0,
  },
  error: {
    backgroundColor: 'rgba(231, 76, 60, 0.1)',
    border: '1px solid #e74c3c',
    borderRadius: '8px',
    padding: '1rem',
    color: '#e74c3c',
    marginBottom: '1.5rem',
    position: 'relative' as const,
  },
  closeButton: {
    position: 'absolute' as const,
    top: '0.5rem',
    right: '0.75rem',
    background: 'none',
    border: 'none',
    color: '#e74c3c',
    fontSize: '1.5rem',
    cursor: 'pointer',
  },
  content: {
    minHeight: '300px',
  },
  step: {
    animation: 'fadeIn 0.3s ease-in',
  },
  stepHeader: {
    textAlign: 'center' as const,
    marginBottom: '2rem',
  },
  stepTitle: {
    fontSize: '1.3rem',
    fontWeight: 'bold',
    color: 'var(--text-color)',
    marginBottom: '0.5rem',
  },
  stepDescription: {
    fontSize: '0.95rem',
    opacity: 0.8,
    lineHeight: 1.5,
    margin: 0,
  },
  form: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '1.5rem',
  },
  inputGroup: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '0.5rem',
  },
  label: {
    fontSize: '0.9rem',
    fontWeight: 'bold',
    color: 'var(--text-color)',
  },
  input: {
    padding: '0.75rem',
    border: '2px solid var(--accent-color)',
    borderRadius: '6px',
    backgroundColor: 'rgba(255, 255, 255, 0.05)',
    color: 'var(--text-color)',
    fontSize: '1rem',
    transition: 'border-color 0.3s ease',
  },
  codeInput: {
    textAlign: 'center' as const,
    fontSize: '1.5rem',
    fontFamily: 'monospace',
    letterSpacing: '0.2em',
  },
  inputHint: {
    fontSize: '0.8rem',
    opacity: 0.7,
    textAlign: 'center' as const,
  },
  formActions: {
    display: 'flex',
    gap: '1rem',
    justifyContent: 'space-between',
  },
  primaryButton: {
    flex: 1,
    padding: '0.75rem 1.5rem',
    backgroundColor: 'var(--accent-color)',
    color: 'var(--bg-color)',
    border: 'none',
    borderRadius: '6px',
    fontSize: '1rem',
    fontWeight: 'bold',
    cursor: 'pointer',
    transition: 'transform 0.2s ease',
  },
  cancelButton: {
    flex: 1,
    padding: '0.75rem 1.5rem',
    backgroundColor: 'transparent',
    color: 'var(--text-color)',
    border: '2px solid rgba(255, 255, 255, 0.3)',
    borderRadius: '6px',
    fontSize: '1rem',
    cursor: 'pointer',
  },
  backButton: {
    flex: 1,
    padding: '0.75rem 1.5rem',
    backgroundColor: 'transparent',
    color: 'var(--text-color)',
    border: '2px solid var(--accent-color)',
    borderRadius: '6px',
    fontSize: '1rem',
    cursor: 'pointer',
  },
  errorState: {
    textAlign: 'center' as const,
    padding: '2rem',
    color: '#e74c3c',
  },
  errorIcon: {
    fontSize: '3rem',
    display: 'block',
    marginBottom: '1rem',
  }
};

export default TwoFactorSetup;
