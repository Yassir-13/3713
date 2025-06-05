// src/components/SessionStatus.tsx - Affichage métadonnées de session
import React from 'react';
import { useSessionMetadata } from '../hooks/useSessionMetadata';

interface SessionStatusProps {
  compact?: boolean;
  showProgress?: boolean;
  showQuota?: boolean;
  showScore?: boolean;
}

const SessionStatus: React.FC<SessionStatusProps> = ({
  compact = false,
  showProgress = true,
  showQuota = true,
  showScore = true
}) => {
  const {
    metadata,
    getProgressPercentage,
    getQuotaStatus,
    getSecurityGrade,
    isScanning,
    hasActiveData
  } = useSessionMetadata();

  if (!hasActiveData && compact) {
    return null; // Ne pas afficher en mode compact si pas de données
  }

  const quotaStatus = getQuotaStatus();
  const progressPercentage = getProgressPercentage();
  const securityGrade = getSecurityGrade();

  // 🎨 Couleurs selon les statuts
  const getQuotaColor = () => {
    switch (quotaStatus) {
      case 'high': return '#2ecc71';
      case 'medium': return '#f39c12';
      case 'low': return '#e67e22';
      case 'empty': return '#e74c3c';
      default: return 'var(--accent-color)';
    }
  };

  const getScoreColor = () => {
    if (metadata.securityScore === null) return 'var(--accent-color)';
    if (metadata.securityScore >= 8) return '#2ecc71';
    if (metadata.securityScore >= 6) return '#f39c12';
    if (metadata.securityScore >= 4) return '#e67e22';
    return '#e74c3c';
  };

  if (compact) {
    return (
      <div style={styles.compactContainer}>
        {showQuota && metadata.remainingScans !== null && (
          <div style={styles.compactItem}>
            <span style={{ color: getQuotaColor() }}>
              {metadata.remainingScans} scans
            </span>
          </div>
        )}
        
        {showProgress && isScanning() && (
          <div style={styles.compactItem}>
            <span style={{ color: '#3498db' }}>
              {progressPercentage}%
            </span>
          </div>
        )}
        
        {showScore && metadata.securityScore !== null && (
          <div style={styles.compactItem}>
            <span style={{ color: getScoreColor() }}>
              {securityGrade}
            </span>
          </div>
        )}
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h4 style={styles.title}>Session Status</h4>
        <div style={styles.timestamp}>
          {metadata.lastUpdate ? 
            `Updated ${Math.floor((Date.now() - metadata.lastUpdate.getTime()) / 1000)}s ago` :
            'No data'
          }
        </div>
      </div>

      <div style={styles.content}>
        {/* 📊 Quotas de scans */}
        {showQuota && (
          <div style={styles.statusItem}>
            <div style={styles.statusIcon}>🎯</div>
            <div style={styles.statusInfo}>
              <div style={styles.statusLabel}>Remaining Scans</div>
              <div style={{ ...styles.statusValue, color: getQuotaColor() }}>
                {metadata.remainingScans !== null ? 
                  `${metadata.remainingScans} left` : 
                  'Loading...'
                }
              </div>
            </div>
            <div style={styles.statusBadge}>
              <span style={{ 
                ...styles.badge, 
                backgroundColor: getQuotaColor() 
              }}>
                {quotaStatus.toUpperCase()}
              </span>
            </div>
          </div>
        )}

        {/* 🔄 Progression du scan */}
        {showProgress && (
          <div style={styles.statusItem}>
            <div style={styles.statusIcon}>
              {isScanning() ? '🔄' : '✅'}
            </div>
            <div style={styles.statusInfo}>
              <div style={styles.statusLabel}>Scan Progress</div>
              <div style={styles.statusValue}>
                {metadata.scanProgress || 'No active scan'}
              </div>
              {isScanning() && (
                <div style={styles.progressBar}>
                  <div 
                    style={{
                      ...styles.progressFill,
                      width: `${progressPercentage}%`
                    }}
                  />
                </div>
              )}
            </div>
            {metadata.currentScanId && (
              <div style={styles.statusMeta}>
                ID: {metadata.currentScanId.substring(0, 8)}...
              </div>
            )}
          </div>
        )}

        {/* 🛡️ Score de sécurité */}
        {showScore && (
          <div style={styles.statusItem}>
            <div style={styles.statusIcon}>🛡️</div>
            <div style={styles.statusInfo}>
              <div style={styles.statusLabel}>Security Score</div>
              <div style={{ ...styles.statusValue, color: getScoreColor() }}>
                {metadata.securityScore !== null ? 
                  `${metadata.securityScore.toFixed(1)}/10` : 
                  'No score yet'
                }
              </div>
            </div>
            <div style={styles.statusBadge}>
              <span style={{ 
                ...styles.badge, 
                backgroundColor: getScoreColor() 
              }}>
                {securityGrade}
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

const styles = {
  container: {
    backgroundColor: 'rgba(255, 255, 255, 0.03)',
    border: '1px solid var(--accent-color)',
    borderRadius: '8px',
    padding: '1rem',
    marginBottom: '1rem',
  },
  compactContainer: {
    display: 'flex',
    gap: '1rem',
    alignItems: 'center',
    fontSize: '0.9rem',
  },
  compactItem: {
    display: 'flex',
    alignItems: 'center',
    fontWeight: 'bold',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '1rem',
    borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
    paddingBottom: '0.5rem',
  },
  title: {
    margin: 0,
    fontSize: '1.1rem',
    color: 'var(--text-color)',
  },
  timestamp: {
    fontSize: '0.8rem',
    opacity: 0.6,
  },
  content: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '0.75rem',
  },
  statusItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    padding: '0.5rem',
    backgroundColor: 'rgba(0, 0, 0, 0.2)',
    borderRadius: '6px',
  },
  statusIcon: {
    fontSize: '1.2rem',
    minWidth: '24px',
  },
  statusInfo: {
    flex: 1,
  },
  statusLabel: {
    fontSize: '0.8rem',
    opacity: 0.7,
    marginBottom: '0.2rem',
  },
  statusValue: {
    fontWeight: 'bold',
    fontSize: '0.9rem',
  },
  statusBadge: {
    marginLeft: 'auto',
  },
  statusMeta: {
    fontSize: '0.7rem',
    opacity: 0.5,
  },
  badge: {
    padding: '0.2rem 0.5rem',
    borderRadius: '12px',
    fontSize: '0.7rem',
    fontWeight: 'bold',
    color: 'white',
  },
  progressBar: {
    marginTop: '0.3rem',
    height: '4px',
    backgroundColor: 'rgba(255, 255, 255, 0.2)',
    borderRadius: '2px',
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    backgroundColor: '#3498db',
    transition: 'width 0.3s ease',
  },
};

export default SessionStatus;