// src/config/api.js - VERSION SÉCURISÉE FINALE
import axios from 'axios';
import secureFingerprinting from '../utils/secureFingerprinting.js';

// 🔒 Configuration sécurisée de base
const api = axios.create({
  baseURL: 'http://localhost:8000/api',
  timeout: 30000, // 30 secondes timeout
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'X-API-Version': 'v1.0',
  }
});

// 🔒 Variables de session sécurisées
let sessionMetadata = {
  scanProgress: null,
  remainingScans: null,
  securityScore: null,
  currentScanId: null,
  lastSecurityCheck: null
};

// 🔒 Anti-double refresh
let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach(prom => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

// 🔒 Initialisation asynchrone du fingerprinting
let clientIdPromise = null;

const getClientId = async () => {
  if (!clientIdPromise) {
    clientIdPromise = secureFingerprinting.generateSecureFingerprint();
  }
  return await clientIdPromise;
};

// 🔒 Intercepteur de requête SÉCURISÉ
api.interceptors.request.use(
  async config => {
    try {
      // Authentification JWT
      const token = localStorage.getItem('token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }

      // Client ID sécurisé
      const clientId = await getClientId();
      config.headers['X-Client-ID'] = clientId;
      
      // Headers contextuels sécurisés
      if (config.url?.includes('/scan')) {
        config.headers['X-Scan-Context'] = 'user_scan';
        
        // Anti-CSRF pour les scans (optionnel avec JWT)
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        if (csrfToken) {
          config.headers['X-CSRF-TOKEN'] = csrfToken;
        }
      }
      
      // Headers de sécurité additionnels
      config.headers['X-Requested-With'] = 'XMLHttpRequest';
      config.headers['Cache-Control'] = 'no-cache';
      
      // Log sécurisé (sans données sensibles)
      console.log('🔒 Secure Request:', {
        url: config.url?.substring(0, 50) + '...',
        method: config.method?.toUpperCase(),
        hasAuth: !!token,
        clientId: clientId?.substring(0, 10) + '...',
        timestamp: new Date().toISOString()
      });
      
      return config;
    } catch (error) {
      console.error("🔒 Request interceptor error:", error);
      return Promise.reject(error);
    }
  },
  error => {
    console.error("❌ Request error:", error);
    return Promise.reject(error);
  }
);

// 🔒 Intercepteur de réponse SÉCURISÉ  
api.interceptors.response.use(
  response => {
    try {
      // Validation de la réponse
      if (!response.headers) {
        console.warn('🔒 Response missing headers');
        return response;
      }

      const headers = response.headers;
      
      // Validation de l'intégrité des headers 3713
      if (headers['x-3713-security'] !== 'enabled') {
        console.warn('🔒 Security header missing - potential proxy/cache issue');
      }

      // Extraction sécurisée des métadonnées
      const newMetadata = { ...sessionMetadata };
      
      if (headers['x-ratelimit-remaining']) {
        const remaining = parseInt(headers['x-ratelimit-remaining']);
        if (!isNaN(remaining) && remaining >= 0) {
          newMetadata.remainingScans = remaining;
        }
      }
      
      if (headers['x-scan-progress']) {
        const progress = headers['x-scan-progress'];
        if (typeof progress === 'string' && progress.length < 50) {
          newMetadata.scanProgress = progress;
        }
      }
      
      if (headers['x-security-score']) {
        const score = parseFloat(headers['x-security-score']);
        if (!isNaN(score) && score >= 0 && score <= 10) {
          newMetadata.securityScore = score;
        }
      }
      
      if (headers['x-scan-id']) {
        const scanId = headers['x-scan-id'];
        if (typeof scanId === 'string' && /^[a-f0-9\-]{36}$/.test(scanId)) {
          newMetadata.currentScanId = scanId;
        }
      }

      // Mise à jour atomique des métadonnées
      sessionMetadata = newMetadata;
      sessionMetadata.lastSecurityCheck = Date.now();
      
      // Dispatch sécurisé des événements
      this.dispatchSecureEvents();
      
      // Log sécurisé de la réponse
      console.log('✅ Secure Response:', {
        status: response.status,
        url: response.config?.url?.substring(0, 50) + '...',
        hasData: !!response.data,
        securityHeader: headers['x-3713-security'],
        responseTime: headers['x-response-time'],
        clientVerified: headers['x-client-verified'] === 'true'
      });
      
      return response;
    } catch (error) {
      console.error('🔒 Response processing error:', error);
      return response; // Retourner la réponse même en cas d'erreur de traitement
    }
  },
  async error => {
    const originalRequest = error.config;
    
    // 🔒 Gestion sécurisée du refresh token
    if (error.response?.status === 401 && !originalRequest._retry && !isRefreshing) {
      
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then(token => {
          originalRequest.headers['Authorization'] = `Bearer ${token}`;
          return api(originalRequest);
        }).catch(err => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const refreshToken = localStorage.getItem('refresh_token');
        if (!refreshToken) {
          throw new Error('No refresh token available');
        }

        console.log('🔄 Refreshing token securely...');
        
        // Requête de refresh avec headers sécurisés
        const refreshResponse = await api.post('/auth/refresh', {
          refresh_token: refreshToken
        }, {
          headers: {
            'X-Client-ID': await getClientId(),
            'X-API-Version': 'v1.0'
          }
        });
        
        const { access_token, refresh_token: newRefreshToken } = refreshResponse.data;
        
        // Sauvegarde sécurisée
        localStorage.setItem('token', access_token);
        if (newRefreshToken) {
          localStorage.setItem('refresh_token', newRefreshToken);
        }
        
        // Mise à jour des headers par défaut
        api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
        originalRequest.headers['Authorization'] = `Bearer ${access_token}`;
        
        processQueue(null, access_token);
        
        console.log('✅ Token refreshed securely');
        return api(originalRequest);
        
      } catch (refreshError) {
        console.error('❌ Secure token refresh failed:', refreshError);
        processQueue(refreshError, null);
        
        // Nettoyage sécurisé
        this.secureLogout();
        
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }
    
    // Log des erreurs avec contexte sécurisé
    console.error('❌ API Error:', {
      status: error.response?.status,
      code: error.response?.data?.code,
      message: error.response?.data?.message?.substring(0, 100),
      url: error.config?.url?.substring(0, 50) + '...'
    });
    
    return Promise.reject(error);
  }
);

// 🔒 Méthodes utilitaires sécurisées
api.dispatchSecureEvents = function() {
  try {
    if (sessionMetadata.remainingScans !== null) {
      window.dispatchEvent(new CustomEvent('quotaUpdate', {
        detail: { remaining: sessionMetadata.remainingScans }
      }));
    }
    
    if (sessionMetadata.scanProgress) {
      window.dispatchEvent(new CustomEvent('scanProgress', {
        detail: { 
          progress: sessionMetadata.scanProgress,
          scanId: sessionMetadata.currentScanId 
        }
      }));
    }
    
    if (sessionMetadata.securityScore !== null) {
      window.dispatchEvent(new CustomEvent('securityScore', {
        detail: { score: sessionMetadata.securityScore }
      }));
    }
  } catch (error) {
    console.error('🔒 Event dispatch error:', error);
  }
};

api.secureLogout = function() {
  // Nettoyage complet et sécurisé
  localStorage.removeItem('token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('user');
  localStorage.removeItem('secure_fingerprint');
  
  // Reset des headers
  delete api.defaults.headers.common['Authorization'];
  
  // Reset des métadonnées
  sessionMetadata = {
    scanProgress: null,
    remainingScans: null,
    securityScore: null,
    currentScanId: null,
    lastSecurityCheck: null
  };
  
  // Redirection sécurisée
  if (window.location.pathname !== '/login') {
    window.location.href = '/login';
  }
};

// 🔒 Validation périodique de sécurité
setInterval(() => {
  if (sessionMetadata.lastSecurityCheck && 
      Date.now() - sessionMetadata.lastSecurityCheck > 300000) { // 5 minutes
    console.log('🔒 Security check timeout - refreshing session');
    api.secureLogout();
  }
}, 60000); // Check chaque minute

// 🔒 Export sécurisé
export const getSessionMetadata = () => ({ ...sessionMetadata });
export const clearSessionMetadata = api.clearSessionMetadata;
export default api;