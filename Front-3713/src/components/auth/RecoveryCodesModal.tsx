// src/components/auth/RecoveryCodesModal.tsx
// 🔑 Modal pour afficher et gérer les codes de récupération A2F
import React, { useState, useEffect } from 'react';
import TwoFactorService from '../../services/TwoFactorService';
import { RecoveryCodesModalProps } from '../../types/twoFactor';

const RecoveryCodesModal: React.FC<RecoveryCodesModalProps> = ({ 
  isOpen, 
  codes, 
  onClose, 
  onDownload 
}) => {
  const [copied, setCopied] = useState(false);
  const [downloaded, setDownloaded] = useState(false);

  // Reset états quand la modal s'ouvre/ferme
  useEffect(() => {
    if (isOpen) {
      setCopied(false);
      setDownloaded(false);
    }
  }, [isOpen]);

  // Copier les codes
  const handleCopy = async () => {
    try {
      const success = await TwoFactorService.copyRecoveryCodes(codes);
      if (success) {
        setCopied(true);
        setTimeout(() => setCopied(false), 3000);
      }
    } catch (error) {
      console.error('Failed to copy codes:', error);
    }
  };

  // Télécharger les codes
  const handleDownload = () => {
    TwoFactorService.downloadRecoveryCodes(codes);
    setDownloaded(true);
    if (onDownload) {
      onDownload();
    }
  };

  // Fermer avec vérification
  const handleClose = () => {
    if (!downloaded && !copied) {
      const confirmed = window.confirm(
        'Are you sure you want to close without saving your recovery codes? ' +
        'You won\'t be able to see them again.'
      );
      if (!confirmed) return;
    }
    onClose();
  };

  // Gérer les clics sur le backdrop
  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      handleClose();
    }
  };

  // Gérer Escape
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        handleClose();
      }
    };

    if (isOpen) {
      document.addEventListener('keydown', handleEscape);
    }

    return () => {
      document.removeEventListener('keydown', handleEscape);
    };
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div style={styles.backdrop} onClick={handleBackdropClick}>
      <div style={styles.modal}>
        
        {/* En-tête */}
        <div style={styles.header}>
          <div style={styles.headerContent}>
            <h3 style={styles.title}>🔑 Recovery Codes</h3>
            <button onClick={handleClose} style={styles.closeButton}>
              ✕
            </button>
          </div>
          
          <div style={styles.warningBanner}>
            <span style={styles.warningIcon}>⚠️</span>
            <div style={styles.warningText}>
              <strong>Important:</strong> Save these codes in a safe place. 
              Each code can only be used once and you won't see them again.
            </div>
          </div>
        </div>

        {/* Contenu */}
        <div style={styles.content}>
          <div style={styles.description}>
            <p>
              These recovery codes can be used to access your account if you lose 
              access to your authenticator device. Each code works only once.
            </p>
          </div>

          {/* Grille des codes */}
          <div style={styles.codesContainer}>
            <div style={styles.codesGrid}>
              {codes.map((code, index) => (
                <div key={index} style={styles.codeItem}>
                  <span style={styles.codeNumber}>{index + 1}.</span>
                  <code style={styles.codeText}>{code}</code>
                </div>
              ))}
            </div>
          </div>

          {/* Actions */}
          <div style={styles.actions}>
            <button
              onClick={handleCopy}
              style={{
                ...styles.actionButton,
                ...styles.copyButton,
                backgroundColor: copied ? '#2ecc71' : '#3498db'
              }}
              disabled={copied}
            >
              {copied ? '✅ Copied to Clipboard' : '📋 Copy All Codes'}
            </button>

            <button
              onClick={handleDownload}
              style={{
                ...styles.actionButton,
                ...styles.downloadButton,
                backgroundColor: downloaded ? '#2ecc71' : 'var(--accent-color)'
              }}
            >
              {downloaded ? '✅ Downloaded' : '💾 Download as File'}
            </button>
          </div>

          {/* Instructions de sécurité */}
          <div style={styles.securityTips}>
            <h4 style={styles.tipsTitle}>🛡️ Security Tips:</h4>
            <ul style={styles.tipsList}>
              <li>Store these codes in a password manager or secure location</li>
              <li>Don't share these codes with anyone</li>
              <li>Each code works only once - they'll be removed after use</li>
              <li>You can regenerate new codes anytime from your security settings</li>
            </ul>
          </div>
        </div>

        {/* Footer */}
        <div style={styles.footer}>
          <div style={styles.footerInfo}>
            <span style={styles.successIcon}>🎉</span>
            <strong>Two-Factor Authentication is now enabled!</strong>
          </div>
          
          <button onClick={onClose} style={styles.doneButton}>
            I've Saved My Codes - Continue
          </button>
        </div>
      </div>
    </div>
  );
};

const styles = {
  backdrop: {
    position: 'fixed' as const,
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.8)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000,
    padding: '1rem',
  },
  modal: {
    backgroundColor: 'var(--bg-color)',
    border: '2px solid var(--accent-color)',
    borderRadius: '12px',
    boxShadow: '0 0 30px rgba(0, 0, 0, 0.5)',
    maxWidth: '600px',
    width: '100%',
    maxHeight: '90vh',
    overflow: 'hidden',
    display: 'flex',
    flexDirection: 'column' as const,
  },
  header: {
    borderBottom: '1px solid var(--accent-color)',
    padding: '1.5rem',
  },
  headerContent: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '1rem',
  },
  title: {
    fontSize: '1.5rem',
    fontWeight: 'bold',
    color: 'var(--text-color)',
    margin: 0,
  },
  closeButton: {
    background: 'none',
    border: 'none',
    color: 'var(--text-color)',
    fontSize: '1.5rem',
    cursor: 'pointer',
    padding: '0.25rem',
    opacity: 0.7,
    transition: 'opacity 0.3s ease',
  },
  warningBanner: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '0.75rem',
    padding: '1rem',
    backgroundColor: 'rgba(255, 193, 7, 0.1)',
    border: '1px solid #ffc107',
    borderRadius: '6px',
  },
  warningIcon: {
    fontSize: '1.2rem',
    flexShrink: 0,
  },
  warningText: {
    fontSize: '0.9rem',
    lineHeight: 1.4,
    color: 'var(--text-color)',
  },
  content: {
    flex: 1,
    padding: '1.5rem',
    overflow: 'auto',
  },
  description: {
    marginBottom: '1.5rem',
    fontSize: '0.95rem',
    lineHeight: 1.5,
    opacity: 0.9,
  },
  codesContainer: {
    marginBottom: '1.5rem',
  },
  codesGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '0.75rem',
  },
  codeItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    padding: '0.75rem',
    backgroundColor: 'rgba(0, 0, 0, 0.2)',
    border: '1px solid rgba(255, 255, 255, 0.2)',
    borderRadius: '6px',
  },
  codeNumber: {
    fontSize: '0.8rem',
    opacity: 0.6,
    minWidth: '1.5rem',
  },
  codeText: {
    fontFamily: 'monospace',
    fontSize: '1rem',
    fontWeight: 'bold',
    color: 'var(--accent-color)',
    backgroundColor: 'transparent',
    letterSpacing: '0.1em',
  },
  actions: {
    display: 'flex',
    gap: '0.75rem',
    marginBottom: '1.5rem',
  },
  actionButton: {
    flex: 1,
    padding: '0.75rem 1rem',
    border: 'none',
    borderRadius: '6px',
    fontSize: '0.9rem',
    fontWeight: 'bold',
    cursor: 'pointer',
    transition: 'background-color 0.3s ease',
    color: 'white',
  },
  copyButton: {
    backgroundColor: '#3498db',
  },
  downloadButton: {
    backgroundColor: 'var(--accent-color)',
  },
  securityTips: {
    backgroundColor: 'rgba(52, 152, 219, 0.05)',
    border: '1px solid rgba(52, 152, 219, 0.2)',
    borderRadius: '6px',
    padding: '1rem',
  },
  tipsTitle: {
    fontSize: '1rem',
    fontWeight: 'bold',
    color: 'var(--text-color)',
    marginBottom: '0.5rem',
  },
  tipsList: {
    margin: 0,
    paddingLeft: '1.5rem',
    fontSize: '0.85rem',
    lineHeight: 1.5,
    opacity: 0.9,
  },
  footer: {
    borderTop: '1px solid var(--accent-color)',
    padding: '1.5rem',
    backgroundColor: 'rgba(0, 0, 0, 0.1)',
  },
  footerInfo: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    marginBottom: '1rem',
    justifyContent: 'center',
    fontSize: '0.95rem',
    color: '#2ecc71',
  },
  successIcon: {
    fontSize: '1.2rem',
  },
  doneButton: {
    width: '100%',
    padding: '0.75rem 1.5rem',
    backgroundColor: '#2ecc71',
    color: 'white',
    border: 'none',
    borderRadius: '6px',
    fontSize: '1rem',
    fontWeight: 'bold',
    cursor: 'pointer',
    transition: 'background-color 0.3s ease',
  },
};

export default RecoveryCodesModal;