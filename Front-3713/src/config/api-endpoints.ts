// src/config/api-endpoints.ts - Version JWT
/**
 * Configuration des endpoints API pour JWT
 * Centralise tous les endpoints de l'API pour faciliter la maintenance
 */

const API_ENDPOINTS = {
  // 🔧 NOUVEAUX : Authentification JWT
  LOGIN: '/auth/login',
  REGISTER: '/auth/register',
  LOGOUT: '/auth/logout',
  ME: '/auth/me',
  REFRESH: '/refresh',
  VERIFY_2FA: '/auth/verify-2fa',
  
  // 🔧 2FA (routes inchangées, mais maintenant protégées par JWT)
  TWO_FACTOR_STATUS: '/2fa/status',
  TWO_FACTOR_GENERATE: '/2fa/generate',
  TWO_FACTOR_CONFIRM: '/2fa/confirm',
  TWO_FACTOR_DISABLE: '/2fa/disable',
  TWO_FACTOR_RECOVERY_CODES: '/2fa/recovery-codes',
  TWO_FACTOR_VERIFY: '/2fa/verify',
  
  // 🔧 Scans (routes inchangées, mais maintenant protégées par JWT)
  START_SCAN: '/scan',
  SCAN_RESULTS: (id: string) => `/scan-results/${id}`,
  SCAN_HISTORY: '/scan-history',
  USER_SCANS: '/user-scans',
  SEARCH_SCANS: '/search-scans',
  GENERATE_REPORT: '/generate-report',
  TOGGLE_FAVORITE: (scanId: string) => `/scan/${scanId}/favorite`,
  FAVORITES: '/favorites',
  
  // 🔧 NOUVEAUX : Routes de debug (optionnelles)
  TEST: '/test',
  JWT_DEBUG: '/jwt-debug',
};

export default API_ENDPOINTS;