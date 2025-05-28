// src/components/auth/QRCodeDisplay.tsx
// 📱 Composant d'affichage QR code et secret manuel
import React, { useState } from 'react';
import { QRCodeDisplayProps } from '../../types/twoFactor';

const QRCodeDisplay: React.FC<QRCodeDisplayProps> = ({ qrCode, secret, onNext }) => {
  const [showSecret, setShowSecret] = useState(false);
  const [secretCopied, setSecretCopied] = useState(false);

  // Copier le secret dans le presse-papiers
  const handleCopySecret = async () => {
    try {
      await navigator.clipboard.writeText(secret);
      setSecretCopied(true);
      setTimeout(() => setSecretCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy secret:', err);
      // Fallback pour les navigateurs plus anciens
      const textArea = document.createElement('textarea');
      textArea.value = secret;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      setSecretCopied(true);
      setTimeout(() => setSecretCopied(false), 2000);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h4 style={styles.title}>📱 Scan QR Code</h4>
        <p style={styles.description}>
          Use your authenticator app to scan this QR code and set up two-factor authentication.
        </p>
      </div>

      {/* QR Code */}
      <div style={styles.qrContainer}>
        <div style={styles.qrWrapper}>
          <img
            src={`data:image/svg+xml;base64,${qrCode}`}
            alt="2FA QR Code"
            style={styles.qrImage}
          />
        </div>
        
        <p style={styles.qrCaption}>
          Scan this QR code with your authenticator app
        </p>
      </div>

      {/* Instructions */}
      <div style={styles.instructions}>
        <h5 style={styles.instructionsTitle}>📋 Instructions:</h5>
        <ol style={styles.instructionsList}>
          <li>Download an authenticator app (Google Authenticator, Authy, etc.)</li>
          <li>Open the app and tap "Add Account" or "+"</li>
          <li>Scan the QR code above with your phone's camera</li>
          <li>Your app will show a 6-digit code that changes every 30 seconds</li>
        </ol>
      </div>

      {/* Alternative : Secret manuel */}
      <div style={styles.manualEntry}>
        <button
          onClick={() => setShowSecret(!showSecret)}
          style={styles.toggleButton}
        >
          {showSecret ? '🔼 Hide' : '🔽 Show'} Manual Entry
        </button>
        
        {showSecret && (
          <div style={styles.secretContainer}>
            <p style={styles.secretLabel}>
              Can't scan? Enter this code manually in your authenticator app:
            </p>
            
            <div style={styles.secretWrapper}>
              <code style={styles.secretCode}>
                {secret.match(/.{1,4}/g)?.join(' ') || secret}
              </code>
              
              <button
                onClick={handleCopySecret}
                style={{
                  ...styles.copyButton,
                  backgroundColor: secretCopied ? '#2ecc71' : 'var(--accent-color)'
                }}
              >
                {secretCopied ? '✅ Copied!' : '📋 Copy'}
              </button>
            </div>
            
            <p style={styles.secretHint}>
              💡 This secret should be entered exactly as shown, without spaces.
            </p>
          </div>
        )}
      </div>

      {/* Apps recommandées */}
      <div style={styles.appsSection}>
        <h5 style={styles.appsTitle}>📲 Recommended Apps:</h5>
        <div style={styles.appsList}>
          <div style={styles.app}>
            <span style={styles.appIcon}>🔐</span>
            <span style={styles.appName}>Google Authenticator</span>
          </div>
          <div style={styles.app}>
            <span style={styles.appIcon}>🛡️</span>
            <span style={styles.appName}>Authy</span>
          </div>
          <div style={styles.app}>
            <span style={styles.appIcon}>🔑</span>
            <span style={styles.appName}>Microsoft Authenticator</span>
          </div>
        </div>
      </div>

      {/* Bouton continuer */}
      <div style={styles.actions}>
        <button onClick={onNext} style={styles.nextButton}>
          I've Added the Account → Continue
        </button>
        
        <p style={styles.nextHint}>
          After adding the account to your app, you'll verify it works with a test code.
        </p>
      </div>
    </div>
  );
};

const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '1.5rem',
    animation: 'fadeIn 0.3s ease-in',
  },
  header: {
    textAlign: 'center' as const,
  },
  title: {
    fontSize: '1.3rem',
    fontWeight: 'bold',
    color: 'var(--text-color)',
    marginBottom: '0.5rem',
  },
  description: {
    fontSize: '0.95rem',
    opacity: 0.8,
    lineHeight: 1.5,
    margin: 0,
  },
  qrContainer: {
    display: 'flex',
    flexDirection: 'column' as const,
    alignItems: 'center',
    gap: '1rem',
  },
  qrWrapper: {
    padding: '1rem',
    backgroundColor: 'white',
    borderRadius: '12px',
    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.2)',
  },
  qrImage: {
    width: '200px',
    height: '200px',
    display: 'block',
  },
  qrCaption: {
    fontSize: '0.9rem',
    opacity: 0.7,
    margin: 0,
    textAlign: 'center' as const,
  },
  instructions: {
    backgroundColor: 'rgba(52, 152, 219, 0.1)',
    border: '1px solid #3498db',
    borderRadius: '8px',
    padding: '1rem',
  },
  instructionsTitle: {
    fontSize: '1rem',
    fontWeight: 'bold',
    color: 'var(--text-color)',
    marginBottom: '0.5rem',
  },
  instructionsList: {
    margin: 0,
    paddingLeft: '1.5rem',
    fontSize: '0.9rem',
    lineHeight: 1.6,
  },
  manualEntry: {
    border: '1px solid rgba(255, 255, 255, 0.2)',
    borderRadius: '8px',
    overflow: 'hidden',
  },
  toggleButton: {
    width: '100%',
    padding: '0.75rem',
    backgroundColor: 'rgba(255, 255, 255, 0.05)',
    color: 'var(--text-color)',
    border: 'none',
    fontSize: '0.9rem',
    cursor: 'pointer',
    transition: 'background-color 0.3s ease',
  },
  secretContainer: {
    padding: '1rem',
    backgroundColor: 'rgba(0, 0, 0, 0.2)',
  },
  secretLabel: {
    fontSize: '0.9rem',
    marginBottom: '0.75rem',
    opacity: 0.9,
  },
  secretWrapper: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    marginBottom: '0.75rem',
  },
  secretCode: {
    flex: 1,
    padding: '0.75rem',
    backgroundColor: 'rgba(0, 0, 0, 0.3)',
    border: '1px solid var(--accent-color)',
    borderRadius: '4px',
    fontFamily: 'monospace',
    fontSize: '0.9rem',
    color: 'var(--text-color)',
    wordBreak: 'break-all' as const,
  },
  copyButton: {
    padding: '0.5rem 0.75rem',
    backgroundColor: 'var(--accent-color)',
    color: 'var(--bg-color)',
    border: 'none',
    borderRadius: '4px',
    fontSize: '0.8rem',
    cursor: 'pointer',
    whiteSpace: 'nowrap' as const,
    transition: 'background-color 0.3s ease',
  },
  secretHint: {
    fontSize: '0.8rem',
    opacity: 0.7,
    margin: 0,
    fontStyle: 'italic',
  },
  appsSection: {
    backgroundColor: 'rgba(255, 255, 255, 0.02)',
    border: '1px solid rgba(255, 255, 255, 0.1)',
    borderRadius: '8px',
    padding: '1rem',
  },
  appsTitle: {
    fontSize: '1rem',
    fontWeight: 'bold',
    color: 'var(--text-color)',
    marginBottom: '0.75rem',
  },
  appsList: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '0.5rem',
  },
  app: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    fontSize: '0.9rem',
  },
  appIcon: {
    fontSize: '1.2rem',
  },
  appName: {
    color: 'var(--text-color)',
  },
  actions: {
    textAlign: 'center' as const,
  },
  nextButton: {
    padding: '0.75rem 2rem',
    backgroundColor: 'var(--accent-color)',
    color: 'var(--bg-color)',
    border: 'none',
    borderRadius: '6px',
    fontSize: '1rem',
    fontWeight: 'bold',
    cursor: 'pointer',
    transition: 'transform 0.2s ease',
    marginBottom: '0.5rem',
  },
  nextHint: {
    fontSize: '0.85rem',
    opacity: 0.7,
    margin: 0,
  },
};

export default QRCodeDisplay;