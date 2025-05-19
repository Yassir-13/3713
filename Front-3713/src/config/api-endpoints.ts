// src/config/api-endpoints.ts
/**
 * Configuration des endpoints API
 * Centralise tous les endpoints de l'API pour faciliter la maintenance
 */

const API_ENDPOINTS = {
  // Authentification
  LOGIN: '/login',
  REGISTER: '/register',
  LOGOUT: '/logout',
  
  // Scans
  START_SCAN: '/scan',
  SCAN_RESULTS: (id: string) => `/scan-results/${id}`,
  SCAN_HISTORY: '/scan-history',
  SEARCH_SCANS: '/search-scans',
};

export default API_ENDPOINTS;