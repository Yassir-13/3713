// src/components/settings/TwoFactorSettings.tsx
import React, { useState, useEffect } from 'react';
import { useTwoFactor } from '../hooks/useTwoFactor';
import TwoFactorSetup from '../components/auth/TwoFactorSetup';
import RecoveryCodesModal from '../components/auth/RecoveryCodesModal';

const TwoFactorSettings: React.FC = () => {
  const {
    status,
    isLoading,
    error,
    loadStatus,
    disableA2F,
    regenerateCodes,
    resetError
  } = useTwoFactor();

  // États locaux
  const [showSetup, setShowSetup] = useState(false);
  const [showDisableForm, setShowDisableForm] = useState(false);
  const [disablePassword, setDisablePassword] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [disableLoading, setDisableLoading] = useState(false);
  const [disableError, setDisableError] = useState('');
  
  // Modal codes de récupération
  const [showRecoveryModal, setShowRecoveryModal] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);

  // Charger le statut au montage
  useEffect(() => {
    loadStatus();
  }, [loadStatus]);

  // Gérer l'activation A2F
  const handleEnableTwoFactor = () => {
    resetError();
    setShowSetup(true);
  };

  // Gérer la désactivation A2F
  const handleDisableTwoFactor = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!disablePassword.trim() || !disableCode.trim()) {
      setDisableError('Password and 2FA code are required');
      return;
    }

    setDisableLoading(true);
    setDisableError('');

    try {
      await disableA2F(disablePassword, disableCode);
      
      // Reset form
      setDisablePassword('');
      setDisableCode('');
      setShowDisableForm(false);
      
      // Recharger le statut
      await loadStatus();
      
    } catch (err: any) {
      setDisableError(err.message || 'Failed to disable 2FA');
    } finally {
      setDisableLoading(false);
    }
  };

  // Gérer la régénération des codes
  const handleRegenerateCodes = async () => {
    const password = prompt('Enter your password to regenerate recovery codes:');
    
    if (!password) return;

    try {
      const newCodes = await regenerateCodes(password);
      setRecoveryCodes(newCodes);
      setShowRecoveryModal(true);
    } catch (err: any) {
      alert(`Failed to regenerate codes: ${err.message}`);
    }
  };

  // Annuler la désactivation
  const handleCancelDisable = () => {
    setShowDisableForm(false);
    setDisablePassword('');
    setDisableCode('');
    setDisableError('');
  };

  // Si wizard A2F ouvert
  if (showSetup) {
    return (
      <TwoFactorSetup
        onComplete={() => {
          setShowSetup(false);
          loadStatus(); // Recharger le statut
        }}
        onCancel={() => setShowSetup(false)}
      />
    );
  }

  return (
    <div style={styles.container}>
      {/* État de chargement */}
      {isLoading && (
        <div style={styles.loading}>
          <div style={styles.spinner}></div>
          <p>Loading 2FA status...</p>
        </div>
      )}

      {/* Erreur générale */}
      {error && (
        <div style={styles.error}>
          <strong>Error:</strong> {error}
          <button onClick={resetError} style={styles.closeButton}>×</button>
        </div>
      )}

      {/* Contenu principal */}
      {!isLoading && status && (
        <div style={styles.content}>
          
          {/* Statut A2F */}
          <div style={styles.statusCard}>
            <div style={styles.statusHeader}>
              <h4 style={styles.statusTitle}>
                {status.enabled ? '🔒 Two-Factor Authentication Enabled' : '🔓 Two-Factor Authentication Disabled'}
              </h4>
              <div style={{
                ...styles.statusBadge,
                backgroundColor: status.enabled ? '#2ecc71' : '#e74c3c'
              }}>
                {status.enabled ? 'Active' : 'Inactive'}
              </div>
            </div>
            
            <p style={styles.statusDescription}>
              {status.enabled 
                ? 'Your account is protected with two-factor authentication.' 
                : 'Add an extra layer of security to your account by enabling 2FA.'}
            </p>

            {status.enabled && status.confirmed_at && (
              <p style={styles.statusMeta}>
                Activated on: {new Date(status.confirmed_at).toLocaleDateString()}
              </p>
            )}
          </div>

          {/* Actions selon le statut */}
          {!status.enabled ? (
            // A2F désactivé - Bouton d'activation
            <div style={styles.actions}>
              <button
                onClick={handleEnableTwoFactor}
                style={styles.primaryButton}
                disabled={isLoading}
              >
                🔐 Enable Two-Factor Authentication
              </button>
              
              <div style={styles.helpText}>
                <p><strong>What is 2FA?</strong></p>
                <p>Two-factor authentication adds an extra security layer by requiring a code from your phone in addition to your password.</p>
              </div>
            </div>
          ) : (
            // A2F activé - Options de gestion
            <div style={styles.actions}>
              
              {/* Régénérer codes de récupération */}
              <div style={styles.actionGroup}>
                <h5 style={styles.actionTitle}>Recovery Codes</h5>
                <p style={styles.actionDescription}>
                  Recovery codes can be used to access your account if you lose your authenticator device.
                </p>
                <button
                  onClick={handleRegenerateCodes}
                  style={styles.secondaryButton}
                  disabled={isLoading}
                >
                  🔄 Regenerate Recovery Codes
                </button>
              </div>

              {/* Désactiver A2F */}
              <div style={styles.actionGroup}>
                <h5 style={styles.actionTitle}>Disable Two-Factor Authentication</h5>
                <p style={styles.actionDescription}>
                  This will remove the extra security layer from your account.
                </p>
                
                {!showDisableForm ? (
                  <button
                    onClick={() => setShowDisableForm(true)}
                    style={styles.dangerButton}
                  >
                    ❌ Disable 2FA
                  </button>
                ) : (
                  // Formulaire de désactivation
                  <form onSubmit={handleDisableTwoFactor} style={styles.disableForm}>
                    {disableError && (
                      <div style={styles.formError}>
                        {disableError}
                      </div>
                    )}
                    
                    <div style={styles.formGroup}>
                      <label style={styles.formLabel}>Current Password:</label>
                      <input
                        type="password"
                        value={disablePassword}
                        onChange={(e) => setDisablePassword(e.target.value)}
                        style={styles.formInput}
                        required
                        disabled={disableLoading}
                      />
                    </div>
                    
                    <div style={styles.formGroup}>
                      <label style={styles.formLabel}>2FA Code:</label>
                      <input
                        type="text"
                        value={disableCode}
                        onChange={(e) => setDisableCode(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
                        style={styles.formInput}
                        placeholder="6-digit code"
                        maxLength={6}
                        required
                        disabled={disableLoading}
                      />
                    </div>
                    
                    <div style={styles.formActions}>
                      <button
                        type="submit"
                        style={styles.dangerButton}
                        disabled={disableLoading || !disablePassword.trim() || !disableCode.trim()}
                      >
                        {disableLoading ? 'Disabling...' : 'Confirm Disable'}
                      </button>
                      
                      <button
                        type="button"
                        onClick={handleCancelDisable}
                        style={styles.cancelButton}
                        disabled={disableLoading}
                      >
                        Cancel
                      </button>
                    </div>
                  </form>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Modal codes de récupération */}
      <RecoveryCodesModal
        isOpen={showRecoveryModal}
        codes={recoveryCodes}
        onClose={() => {
          setShowRecoveryModal(false);
          setRecoveryCodes([]);
        }}
      />
    </div>
  );
};

const styles = {
  container: {
    backgroundColor: 'rgba(255, 255, 255, 0.03)',
    border: '1px solid var(--accent-color)',
    borderRadius: '12px',
    padding: '1.5rem',
  },
  loading: {
    textAlign: 'center' as const,
    padding: '2rem',
    opacity: 0.7,
  },
  spinner: {
    width: '32px',
    height: '32px',
    border: '3px solid rgba(255, 255, 255, 0.3)',
    borderTop: '3px solid var(--accent-color)',
    borderRadius: '50%',
    animation: 'spin 1s linear infinite',
    margin: '0 auto 1rem',
  },
  error: {
    backgroundColor: 'rgba(231, 76, 60, 0.1)',
    border: '1px solid #e74c3c',
    borderRadius: '8px',
    padding: '1rem',
    color: '#e74c3c',
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
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '1.5rem',
  },
  statusCard: {
    padding: '1rem',
    borderRadius: '8px',
    backgroundColor: 'rgba(0, 0, 0, 0.2)',
  },
  statusHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '0.5rem',
  },
  statusTitle: {
    margin: 0,
    fontSize: '1.2rem',
    color: 'var(--text-color)',
  },
  statusBadge: {
    padding: '0.25rem 0.75rem',
    borderRadius: '20px',
    fontSize: '0.8rem',
    fontWeight: 'bold',
    color: 'white',
  },
  statusDescription: {
    margin: '0.5rem 0',
    opacity: 0.8,
  },
  statusMeta: {
    margin: 0,
    fontSize: '0.85rem',
    opacity: 0.6,
  },
  actions: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '1.5rem',
  },
  actionGroup: {
    padding: '1rem',
    borderRadius: '8px',
    backgroundColor: 'rgba(255, 255, 255, 0.02)',
    border: '1px solid rgba(255, 255, 255, 0.1)',
  },
  actionTitle: {
    margin: '0 0 0.5rem 0',
    fontSize: '1rem',
    fontWeight: 'bold',
    color: 'var(--text-color)',
  },
  actionDescription: {
    margin: '0 0 1rem 0',
    fontSize: '0.9rem',
    opacity: 0.8,
  },
  primaryButton: {
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
  secondaryButton: {
    padding: '0.5rem 1rem',
    backgroundColor: 'transparent',
    color: 'var(--text-color)',
    border: '1px solid var(--accent-color)',
    borderRadius: '6px',
    fontSize: '0.9rem',
    cursor: 'pointer',
  },
  dangerButton: {
    padding: '0.5rem 1rem',
    backgroundColor: '#e74c3c',
    color: 'white',
    border: 'none',
    borderRadius: '6px',
    fontSize: '0.9rem',
    cursor: 'pointer',
  },
  cancelButton: {
    padding: '0.5rem 1rem',
    backgroundColor: 'transparent',
    color: 'var(--text-color)',
    border: '1px solid rgba(255, 255, 255, 0.3)',
    borderRadius: '6px',
    fontSize: '0.9rem',
    cursor: 'pointer',
  },
  helpText: {
    marginTop: '1rem',
    padding: '1rem',
    backgroundColor: 'rgba(52, 152, 219, 0.1)',
    border: '1px solid #3498db',
    borderRadius: '6px',
    fontSize: '0.9rem',
  },
  disableForm: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '1rem',
    marginTop: '1rem',
  },
  formError: {
    backgroundColor: 'rgba(231, 76, 60, 0.1)',
    border: '1px solid #e74c3c',
    borderRadius: '4px',
    padding: '0.5rem',
    color: '#e74c3c',
    fontSize: '0.9rem',
  },
  formGroup: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '0.5rem',
  },
  formLabel: {
    fontSize: '0.9rem',
    fontWeight: 'bold',
    color: 'var(--text-color)',
  },
  formInput: {
    padding: '0.5rem',
    border: '1px solid var(--accent-color)',
    borderRadius: '4px',
    backgroundColor: 'rgba(255, 255, 255, 0.05)',
    color: 'var(--text-color)',
    fontSize: '0.9rem',
  },
  formActions: {
    display: 'flex',
    gap: '0.5rem',
  },
};

export default TwoFactorSettings;