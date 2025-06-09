// src/services/TwoFactorService.ts
// 🔐 Service API pour le système A2F 3713 - Version JWT

import api from '../config/api';
import { 
  TwoFactorStatus, 
  TwoFactorSetupData, 
  TwoFactorConfirmResult,
  VerifyCodeResponse,
  RecoveryCodesData,
  TwoFactorError
} from '../types/twoFactor';

class TwoFactorService {
  
  async getStatus(): Promise<TwoFactorStatus> {
    try {
      const response = await api.get('/2fa/status');
      return response.data;
    } catch (error: any) {
      console.error('Error getting 2FA status:', error);
      throw this.handleError(error);
    }
  }

  async generateSecret(password: string): Promise<TwoFactorSetupData> {
    try {
      const response = await api.post('/2fa/generate', { password });
      return response.data;
    } catch (error: any) {
      console.error('Error generating 2FA secret:', error);
      throw this.handleError(error);
    }
  }

  async confirmTwoFactor(code: string): Promise<TwoFactorConfirmResult> {
    try {
      const response = await api.post('/2fa/confirm', { code });
      return response.data;
    } catch (error: any) {
      console.error('Error confirming 2FA:', error);
      throw this.handleError(error);
    }
  }

  async disableTwoFactor(password: string, code: string): Promise<{ message: string; enabled: boolean }> {
    try {
      const response = await api.post('/2fa/disable', { password, code });
      return response.data;
    } catch (error: any) {
      console.error('Error disabling 2FA:', error);
      throw this.handleError(error);
    }
  }

  async regenerateRecoveryCodes(password: string): Promise<RecoveryCodesData> {
    try {
      const response = await api.post('/2fa/recovery-codes', { password });
      return response.data;
    } catch (error: any) {
      console.error('Error regenerating recovery codes:', error);
      throw this.handleError(error);
    }
  }

  async verifyCode(userId: number, code: string): Promise<VerifyCodeResponse> {
    try {
      const response = await api.post('/2fa/verify', { user_id: userId, code });
      return response.data;
    } catch (error: any) {
      console.error('Error verifying 2FA code:', error);
      throw this.handleError(error);
    }
  }

  async loginWithTwoFactor(email: string, password: string, twoFactorCode?: string) {
    try {
      const response = await api.post('/auth/login', {
        email,
        password,
        two_factor_code: twoFactorCode
      });
      return response.data;
    } catch (error: any) {
      console.error('Error during 2FA login:', error);
      throw this.handleError(error);
    }
  }

  private handleError(error: any): TwoFactorError {
    if (error.response && error.response.data) {
      return {
        message: error.response.data.message || 'An error occurred',
        error: error.response.data.error,
        field: error.response.data.field
      };
    }
    
    if (error.request) {
      return {
        message: 'Network error. Please check your connection.',
        error: 'NETWORK_ERROR'
      };
    }
    
    return {
      message: error.message || 'An unexpected error occurred',
      error: 'UNKNOWN_ERROR'
    };
  }

  downloadRecoveryCodes(codes: string[]): void {
    const content = [
      '=== 3713 Two-Factor Recovery Codes ===',
      '',
      'IMPORTANT: Keep these codes safe and secure!',
      'Each code can only be used once.',
      '',
      'Recovery Codes:',
      ...codes.map((code, index) => `${index + 1}. ${code}`),
      '',
      `Generated: ${new Date().toLocaleString()}`,
      '',
      'If you lose access to your authenticator app,',
      'you can use these codes to regain access to your account.'
    ].join('\n');

    const blob = new Blob([content], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    
    link.href = url;
    link.download = `3713-recovery-codes-${new Date().toISOString().split('T')[0]}.txt`;
    link.click();
    
    window.URL.revokeObjectURL(url);
  }

  /**
   * Copier les codes dans le presse-papiers
   */
  async copyRecoveryCodes(codes: string[]): Promise<boolean> {
    try {
      const text = codes.join('\n');
      await navigator.clipboard.writeText(text);
      return true;
    } catch (error) {
      console.error('Failed to copy recovery codes:', error);
      return false;
    }
  }

  /**
   * Valider format du code A2F
   */
  validateTwoFactorCode(code: string): { valid: boolean; message: string } {
    if (!code || code.trim() === '') {
      return { valid: false, message: 'Code is required' };
    }

    const cleanCode = code.replace(/\s/g, '');

    // Code TOTP (6 chiffres)
    if (/^\d{6}$/.test(cleanCode)) {
      return { valid: true, message: 'Valid TOTP code format' };
    }

    // Code de récupération (8 caractères alphanumériques)
    if (/^[A-Z0-9]{8}$/.test(cleanCode.toUpperCase())) {
      return { valid: true, message: 'Valid recovery code format' };
    }

    return { 
      valid: false, 
      message: 'Code must be 6 digits (from app) or 8 characters (recovery code)' 
    };
  }
}

// Export singleton
export default new TwoFactorService();