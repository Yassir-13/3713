// src/hooks/useSessionMetadata.ts - Hook pour utiliser les headers sécurisés
import { useState, useEffect } from 'react';

interface SessionMetadata {
  remainingScans: number | null;
  scanProgress: string | null;
  securityScore: number | null;
  currentScanId: string | null;
  lastUpdate: Date | null;
}

export const useSessionMetadata = () => {
  const [metadata, setMetadata] = useState<SessionMetadata>({
    remainingScans: null,
    scanProgress: null,
    securityScore: null,
    currentScanId: null,
    lastUpdate: null
  });

  useEffect(() => {
    // 🎯 Écouter les événements de mise à jour des quotas
    const handleQuotaUpdate = (event: CustomEvent) => {
      setMetadata(prev => ({
        ...prev,
        remainingScans: event.detail.remaining,
        lastUpdate: new Date()
      }));
    };

    // 🎯 Écouter les événements de progression de scan
    const handleScanProgress = (event: CustomEvent) => {
      setMetadata(prev => ({
        ...prev,
        scanProgress: event.detail.progress,
        currentScanId: event.detail.scanId,
        lastUpdate: new Date()
      }));
    };

    // 🎯 Écouter les événements de score de sécurité
    const handleSecurityScore = (event: CustomEvent) => {
      setMetadata(prev => ({
        ...prev,
        securityScore: event.detail.score,
        lastUpdate: new Date()
      }));
    };

    // 📡 Ajouter les listeners
    window.addEventListener('quotaUpdate', handleQuotaUpdate as EventListener);
    window.addEventListener('scanProgress', handleScanProgress as EventListener);
    window.addEventListener('securityScore', handleSecurityScore as EventListener);

    // 🧹 Cleanup
    return () => {
      window.removeEventListener('quotaUpdate', handleQuotaUpdate as EventListener);
      window.removeEventListener('scanProgress', handleScanProgress as EventListener);
      window.removeEventListener('securityScore', handleSecurityScore as EventListener);
    };
  }, []);

  // 🎨 Fonctions utilitaires pour l'affichage
  const getProgressPercentage = (): number => {
    if (!metadata.scanProgress) return 0;
    const match = metadata.scanProgress.match(/(\d+)/);
    return match ? parseInt(match[1]) : 0;
  };

  const getQuotaStatus = (): 'high' | 'medium' | 'low' | 'empty' => {
    if (metadata.remainingScans === null) return 'medium';
    if (metadata.remainingScans === 0) return 'empty';
    if (metadata.remainingScans <= 2) return 'low';
    if (metadata.remainingScans <= 5) return 'medium';
    return 'high';
  };

  const getSecurityGrade = (): string => {
    if (metadata.securityScore === null) return 'N/A';
    if (metadata.securityScore >= 9) return 'A+';
    if (metadata.securityScore >= 8) return 'A';
    if (metadata.securityScore >= 7) return 'B+';
    if (metadata.securityScore >= 6) return 'B';
    if (metadata.securityScore >= 5) return 'C';
    if (metadata.securityScore >= 4) return 'D';
    return 'F';
  };

  const isScanning = (): boolean => {
    return metadata.scanProgress !== null && 
           !metadata.scanProgress.includes('100%') &&
           !metadata.scanProgress.includes('completed');
  };

  return {
    metadata,
    
    // 🎨 Fonctions utilitaires
    getProgressPercentage,
    getQuotaStatus,
    getSecurityGrade,
    isScanning,
    
    // 🔍 État calculé
    hasActiveData: metadata.lastUpdate !== null,
    timeSinceLastUpdate: metadata.lastUpdate 
      ? Math.floor((Date.now() - metadata.lastUpdate.getTime()) / 1000)
      : null
  };
};