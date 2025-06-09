// src/config/api.js - INTERCEPTEUR CORRIGÉ

import axios from 'axios';
import secureFingerprinting from '../utils/secureFingerprinting.js';

const api = axios.create({
  baseURL: 'http://localhost:8000/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'X-API-Version': 'v1.0',
  }
});

let sessionMetadata = {
  scanProgress: null,
  remainingScans: null,
  securityScore: null,
  currentScanId: null,
  lastSecurityCheck: null
};

let isRefreshing = false;
let failedQueue = [];
let clientIdPromise = null;

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

const getClientId = async () => {
  if (!clientIdPromise) {
    clientIdPromise = secureFingerprinting.generateSecureFingerprint();
  }
  return await clientIdPromise;
};

// 🔧 INTERCEPTEUR DE REQUÊTE CORRIGÉ
api.interceptors.request.use(
  async config => {
    try {
      config.headers['X-API-Version'] = 'v1.0';
      
      const token = localStorage.getItem('token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }

      try {
        const clientId = await getClientId();
        if (clientId) {
          config.headers['X-Client-ID'] = clientId;
        }
      } catch (e) {
        console.warn('🔧 Client-ID generation failed (non-blocking):', e.message);
      }
      
      if (config.url?.includes('/scan')) {
        config.headers['X-Scan-Context'] = 'user_scan';
      }
      
      config.headers['X-Requested-With'] = 'XMLHttpRequest';
      config.headers['Cache-Control'] = 'no-cache';
      
      console.log('🔒 Request headers:', {
        url: config.url?.substring(0, 50) + '...',
        method: config.method?.toUpperCase(),
        hasAuth: !!token,
        hasApiVersion: !!config.headers['X-API-Version'],
        hasClientId: !!config.headers['X-Client-ID'],
      });
      
      return config;
    } catch (error) {
      console.error("🔒 Request interceptor error:", error);
      // 🔧 CORRECTION : Continuer même en cas d'erreur au lieu de rejeter
      return config;
    }
  },
  error => Promise.reject(error)
);

// Obtenir header case-insensitive
const getHeaderCaseInsensitive = (headers, headerName) => {
  const lowerHeaderName = headerName.toLowerCase();
  
  if (headers[lowerHeaderName] !== undefined) {
    return headers[lowerHeaderName];
  }
  
  const variations = [
    headerName,
    headerName.toLowerCase(),
    headerName.toUpperCase(),
    headerName.toLowerCase().replace(/(^|-)([a-z])/g, (match, p1, p2) => p1 + p2.toUpperCase())
  ];
  
  for (const variation of variations) {
    if (headers[variation] !== undefined) {
      console.log(`🔧 Found header ${headerName} as ${variation}:`, headers[variation]);
      return headers[variation];
    }
  }
  
  return undefined;
};

// Debug headers reçus
const debugHeaders = (headers, context = '') => {
  if (process.env.NODE_ENV === 'development') {
    const relevantHeaders = {};
    const headerNames = [
      'x-ratelimit-remaining', 'x-scan-progress', 'x-security-score', 
      'x-scan-id', 'x-3713-security', 'x-client-verified'
    ];
    
    headerNames.forEach(name => {
      const value = getHeaderCaseInsensitive(headers, name);
      if (value !== undefined) {
        relevantHeaders[name] = value;
      }
    });
    
    if (Object.keys(relevantHeaders).length > 0) {
      console.log(`🔧 Headers received ${context}:`, relevantHeaders);
    }
  }
};

// 🔧 INTERCEPTEUR DE RÉPONSE SIMPLIFIÉ
api.interceptors.response.use(
  response => {
    try {
      if (!response.headers) {
        console.warn('🔒 Response missing headers');
        return response;
      }

      const headers = response.headers;
      debugHeaders(headers, `from ${response.config?.url}`);
      
      // Validation de l'intégrité
      const securityHeader = getHeaderCaseInsensitive(headers, 'x-3713-security');
      if (securityHeader !== 'enabled') {
        console.warn('🔒 Security header missing or invalid:', securityHeader);
      }

      // Extraction métadonnées avec case-insensitive
      const newMetadata = { ...sessionMetadata };
      
      const remainingHeader = getHeaderCaseInsensitive(headers, 'x-ratelimit-remaining');
      if (remainingHeader) {
        const remaining = parseInt(remainingHeader);
        if (!isNaN(remaining) && remaining >= 0) {
          newMetadata.remainingScans = remaining;
        }
      }
      
      const progressHeader = getHeaderCaseInsensitive(headers, 'x-scan-progress');
      if (progressHeader && typeof progressHeader === 'string' && progressHeader.length < 50) {
        newMetadata.scanProgress = progressHeader;
      }
      
      const scoreHeader = getHeaderCaseInsensitive(headers, 'x-security-score');
      if (scoreHeader) {
        const score = parseFloat(scoreHeader);
        if (!isNaN(score) && score >= 0 && score <= 10) {
          newMetadata.securityScore = score;
        }
      }
      
      const scanIdHeader = getHeaderCaseInsensitive(headers, 'x-scan-id');
      if (scanIdHeader && typeof scanIdHeader === 'string' && /^[a-f0-9\-]{36}$/.test(scanIdHeader)) {
        newMetadata.currentScanId = scanIdHeader;
      }

      sessionMetadata = newMetadata;
      sessionMetadata.lastSecurityCheck = Date.now();
      
      api.dispatchSecureEvents();
      
      return response;
    } catch (error) {
      console.error('🔒 Response processing error:', error);
      return response;
    }
  },
  async error => {
    const originalRequest = error.config;
    
    // 🔧 REFRESH TOKEN SIMPLIFIÉ
    if (error.response?.status === 401 && !originalRequest._retry && !isRefreshing) {
      
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then(token => {
          originalRequest.headers['Authorization'] = `Bearer ${token}`;
          originalRequest.headers['X-API-Version'] = 'v1.0'; // 🔧 AJOUTÉ
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

        console.log('🔄 Refreshing token...');
        
        const refreshResponse = await api.post('/auth/refresh', {
          refresh_token: refreshToken
        }, {
          headers: {
            'X-API-Version': 'v1.0', // 🔧 AJOUTÉ pour refresh
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          }
        });
        
        const { access_token, refresh_token: newRefreshToken } = refreshResponse.data;
        
        localStorage.setItem('token', access_token);
        if (newRefreshToken) {
          localStorage.setItem('refresh_token', newRefreshToken);
        }
        
        api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
        originalRequest.headers['Authorization'] = `Bearer ${access_token}`;
        originalRequest.headers['X-API-Version'] = 'v1.0'; // 🔧 AJOUTÉ
        
        processQueue(null, access_token);
        
        console.log('✅ Token refreshed');
        return api(originalRequest);
        
      } catch (refreshError) {
        console.error('❌ Token refresh failed:', refreshError);
        processQueue(refreshError, null);
        api.secureLogout();
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }
    
    console.error('❌ API Error:', {
      status: error.response?.status,
      message: error.response?.data?.message?.substring(0, 100),
      url: error.config?.url?.substring(0, 50) + '...'
    });
    
    return Promise.reject(error);
  }
);

// Méthodes utilitaires (identiques)
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
  localStorage.removeItem('token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('user');
  localStorage.removeItem('secure_fingerprint');
  
  delete api.defaults.headers.common['Authorization'];
  
  sessionMetadata = {
    scanProgress: null,
    remainingScans: null,
    securityScore: null,
    currentScanId: null,
    lastSecurityCheck: null
  };
  
  if (window.location.pathname !== '/login') {
    window.location.href = '/login';
  }
};

// Validation périodique de sécurité
setInterval(() => {
  if (sessionMetadata.lastSecurityCheck && 
      Date.now() - sessionMetadata.lastSecurityCheck > 300000) {
    console.log('🔒 Security check timeout - refreshing session');
    api.secureLogout();
  }
}, 60000);

export const getSessionMetadata = () => ({ ...sessionMetadata });
export default api;