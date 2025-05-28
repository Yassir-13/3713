// src/types/twoFactor.ts
// 🔐 Types pour le système A2F 3713

export interface TwoFactorStatus {
  enabled: boolean;
  confirmed_at: string | null;
  has_recovery_codes: boolean;
}

export interface TwoFactorSetupData {
  secret: string;
  qr_code: string; // Base64 SVG
  backup_codes: string[];
}

export interface TwoFactorConfirmResult {
  message: string;
  backup_codes: string[];
  enabled: boolean;
}

export interface TwoFactorUser {
  id: number;
  name: string;
  email: string;
  two_factor_enabled: boolean;
}

// États du processus A2F
export type TwoFactorStep = 
  | 'password_verification'
  | 'qr_code_display' 
  | 'code_confirmation'
  | 'recovery_codes_display'
  | 'completed'
  | 'error';

// États du login A2F
export type LoginState = 
  | 'credentials'
  | 'two_factor_required'
  | 'verifying'
  | 'success'
  | 'error';

// Réponse API login
export interface LoginResponse {
  message: string;
  user?: TwoFactorUser;
  token?: string;
  requires_2fa?: boolean;
  user_id?: number;
}

// Réponse vérification code
export interface VerifyCodeResponse {
  valid: boolean;
  message: string;
  remaining_codes?: number;
}

// Données recovery codes
export interface RecoveryCodesData {
  backup_codes: string[];
  message: string;
}

// Erreur API A2F
export interface TwoFactorError {
  message: string;
  error?: string;
  field?: string;
}

// Props composants
export interface TwoFactorSetupProps {
  onComplete: () => void;
  onCancel: () => void;
}

export interface TwoFactorLoginProps {
  userId: number;
  onSuccess: (user: TwoFactorUser, token: string) => void;
  onCancel: () => void;
}

export interface QRCodeDisplayProps {
  qrCode: string; // Base64 SVG
  secret: string;
  onNext: () => void;
}

export interface RecoveryCodesModalProps {
  isOpen: boolean;
  codes: string[];
  onClose: () => void;
  onDownload?: () => void;
}