// src/hooks/useTwoFactor.ts


import { useState, useEffect, useCallback } from 'react';
import TwoFactorService from '../services/TwoFactorService';
import { 
  TwoFactorStatus, 
  TwoFactorSetupData, 
  TwoFactorStep,
  TwoFactorError 
} from '../types/twoFactor';

interface UseTwoFactorReturn {
  // État actuel
  status: TwoFactorStatus | null;
  setupData: TwoFactorSetupData | null;
  currentStep: TwoFactorStep;
  isLoading: boolean;
  error: string | null;

  // Actions principales
  loadStatus: () => Promise<void>;
  generateSecret: (password: string) => Promise<void>;
  confirmSetup: (code: string) => Promise<string[]>; // Retourne les codes de récup
  disableA2F: (password: string, code: string) => Promise<void>;
  regenerateCodes: (password: string) => Promise<string[]>;
  verifyCode: (userId: number, code: string) => Promise<boolean>;

  // Utilitaires
  resetError: () => void;
  resetSetup: () => void;
  setStep: (step: TwoFactorStep) => void;
}

export const useTwoFactor = (): UseTwoFactorReturn => {
  // États principaux
  const [status, setStatus] = useState<TwoFactorStatus | null>(null);
  const [setupData, setSetupData] = useState<TwoFactorSetupData | null>(null);
  const [currentStep, setCurrentStep] = useState<TwoFactorStep>('password_verification');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);


  const loadStatus = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      
      const statusData = await TwoFactorService.getStatus();
      setStatus(statusData);
      
    } catch (err: any) {
      console.error('Failed to load 2FA status:', err);
      setError(err.message || 'Failed to load 2FA status');
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * 🔑 Générer secret et QR code
   */
  const generateSecret = useCallback(async (password: string) => {
    try {
      setIsLoading(true);
      setError(null);
      
      const data = await TwoFactorService.generateSecret(password);
      setSetupData(data);
      setCurrentStep('qr_code_display');
      
    } catch (err: any) {
      console.error('Failed to generate secret:', err);
      setError(err.message || 'Failed to generate 2FA secret');
      setCurrentStep('error');
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * ✅ Confirmer et activer l'A2F
   */
  const confirmSetup = useCallback(async (code: string): Promise<string[]> => {
    try {
      setIsLoading(true);
      setError(null);
      
      const result = await TwoFactorService.confirmTwoFactor(code);
      
      // Mettre à jour le statut local
      setStatus(prev => prev ? { ...prev, enabled: true } : null);
      setCurrentStep('recovery_codes_display');
      
      return result.backup_codes;
      
    } catch (err: any) {
      console.error('Failed to confirm 2FA:', err);
      setError(err.message || 'Failed to confirm 2FA setup');
      throw err; // Re-throw pour que le composant puisse gérer
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * ❌ Désactiver l'A2F
   */
  const disableA2F = useCallback(async (password: string, code: string) => {
    try {
      setIsLoading(true);
      setError(null);
      
      await TwoFactorService.disableTwoFactor(password, code);
      
      // Mettre à jour le statut local
      setStatus(prev => prev ? { ...prev, enabled: false } : null);
      
      // Reset des données de setup
      setSetupData(null);
      setCurrentStep('password_verification');
      
    } catch (err: any) {
      console.error('Failed to disable 2FA:', err);
      setError(err.message || 'Failed to disable 2FA');
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * 🔄 Régénérer codes de récupération
   */
  const regenerateCodes = useCallback(async (password: string): Promise<string[]> => {
    try {
      setIsLoading(true);
      setError(null);
      
      const result = await TwoFactorService.regenerateRecoveryCodes(password);
      return result.backup_codes;
      
    } catch (err: any) {
      console.error('Failed to regenerate codes:', err);
      setError(err.message || 'Failed to regenerate recovery codes');
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * 🔍 Vérifier un code A2F
   */
  const verifyCode = useCallback(async (userId: number, code: string): Promise<boolean> => {
    try {
      setIsLoading(true);
      setError(null);
      
      const result = await TwoFactorService.verifyCode(userId, code);
      return result.valid;
      
    } catch (err: any) {
      console.error('Failed to verify code:', err);
      setError(err.message || 'Failed to verify code');
      return false;
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * 🛠️ Utilitaires
   */
  const resetError = useCallback(() => {
    setError(null);
  }, []);

  const resetSetup = useCallback(() => {
    setSetupData(null);
    setCurrentStep('password_verification');
    setError(null);
  }, []);

  const setStep = useCallback((step: TwoFactorStep) => {
    setCurrentStep(step);
  }, []);

  // Charger le statut au montage du hook
  useEffect(() => {
    loadStatus();
  }, [loadStatus]);

  return {
    // État
    status,
    setupData,
    currentStep,
    isLoading,
    error,

    // Actions
    loadStatus,
    generateSecret,
    confirmSetup,
    disableA2F,
    regenerateCodes,
    verifyCode,

    // Utilitaires
    resetError,
    resetSetup,
    setStep
  };
};

// Hook pour login A2F (version simplifiée)
export const useTwoFactorLogin = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loginWithTwoFactor = useCallback(async (
    email: string, 
    password: string, 
    twoFactorCode?: string
  ) => {
    try {
      setIsLoading(true);
      setError(null);
      
      const result = await TwoFactorService.loginWithTwoFactor(email, password, twoFactorCode);
      return result;
      
    } catch (err: any) {
      console.error('2FA Login failed:', err);
      setError(err.message || 'Login failed');
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const resetError = useCallback(() => {
    setError(null);
  }, []);

  return {
    loginWithTwoFactor,
    isLoading,
    error,
    resetError
  };
};