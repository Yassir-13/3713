// src/config/api.js - VERSION FINALE avec headers sécurisés 3713
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000/api',
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'X-API-Version': 'v1',                    // 🆕 Versioning API
    'X-Client-ID': generateClientFingerprint() // 🆕 Client unique ID
  }
});

//Génération d'un fingerprint client unique
function generateClientFingerprint() {
  // Créer un ID unique basé sur le navigateur
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  ctx.textBaseline = 'top';
  ctx.font = '14px Arial';
  ctx.fillText('3713-fingerprint', 2, 2);
  
  const fingerprint = [
    navigator.userAgent,
    navigator.language,
    screen.width + 'x' + screen.height,
    new Date().getTimezoneOffset(),
    canvas.toDataURL()
  ].join('|');
  
  // Hash simple pour ID court
  let hash = 0;
  for (let i = 0; i < fingerprint.length; i++) {
    const char = fingerprint.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  
  return 'client_' + Math.abs(hash).toString(16);
}

//Stockage des metadata de session
let sessionMetadata = {
  scanProgress: null,
  remainingScans: null,
  securityScore: null,
  currentScanId: null
};

// Variable pour éviter les appels multiples de refresh
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

// 🔧 Intercepteur de requête avec headers sécurisés
api.interceptors.request.use(
  config => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers = config.headers || {};
      config.headers.Authorization = `Bearer ${token}`;
    }
    
    //Headers contextuels selon l'endpoint
    if (config.url && config.url.includes('/scan')) {
      config.headers['X-Scan-Context'] = 'user_scan';
    }
    
    console.log('🚀 Request:', {
      url: config.url,
      method: config.method,
      hasAuth: !!token,
      clientId: config.headers['X-Client-ID']?.substr(0, 12) + '...'
    });
    
    return config;
  },
  error => {
    console.error("❌ Request interceptor error:", error);
    return Promise.reject(error);
  }
);

// 🔧 Intercepteur de réponse avec extraction des headers
api.interceptors.response.use(
  response => {
    //Extraction automatique des headers exposés
    const headers = response.headers;
    
    // Mise à jour des metadata de session
    if (headers['x-ratelimit-remaining']) {
      sessionMetadata.remainingScans = parseInt(headers['x-ratelimit-remaining']);
    }
    
    if (headers['x-scan-progress']) {
      sessionMetadata.scanProgress = headers['x-scan-progress'];
    }
    
    if (headers['x-security-score']) {
      sessionMetadata.securityScore = parseFloat(headers['x-security-score']);
    }
    
    if (headers['x-scan-id']) {
      sessionMetadata.currentScanId = headers['x-scan-id'];
    }
    
    //Log enrichi pour debug
    console.log('✅ Response:', {
      status: response.status,
      url: response.config.url,
      scanProgress: sessionMetadata.scanProgress,
      remainingScans: sessionMetadata.remainingScans,
      securityScore: sessionMetadata.securityScore,
      responseTime: headers['x-response-time']
    });
    
    //Dispatch d'événements pour mise à jour UI
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
    
    return response;
  },
  async error => {
    const originalRequest = error.config;
    
    // Gérer les erreurs d'authentification (401)
    if (error.response && error.response.status === 401 && !originalRequest._retry) {
      
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then(token => {
          originalRequest.headers['Authorization'] = `Bearer ${token}`;
          return api(originalRequest);
        }).catch(err => {
          return Promise.reject(err);
        });
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
        });
        
        const newToken = refreshResponse.data.access_token;
        const newRefreshToken = refreshResponse.data.refresh_token;
        
        // Sauvegarder les nouveaux tokens
        localStorage.setItem('token', newToken);
        localStorage.setItem('refresh_token', newRefreshToken);
        
        // Mettre à jour le header Authorization
        api.defaults.headers.common['Authorization'] = `Bearer ${newToken}`;
        originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
        
        processQueue(null, newToken);
        
        console.log('✅ Token refreshed successfully');
        return api(originalRequest);
        
      } catch (refreshError) {
        console.error('❌ Token refresh failed:', refreshError);
        processQueue(refreshError, null);
        
        // Nettoyer le localStorage
        localStorage.removeItem('token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
        
        // Rediriger vers login si possible
        if (window.location.pathname !== '/login') {
          window.location.href = '/login';
        }
        
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }
    
    //Log des erreurs avec context enrichi
    console.error('❌ API Error:', {
      status: error.response?.status,
      url: error.config?.url,
      method: error.config?.method,
      message: error.response?.data?.message || error.message,
      remainingScans: sessionMetadata.remainingScans
    });
    
    return Promise.reject(error);
  }
);

//Export des metadata pour utilisation dans les composants
export const getSessionMetadata = () => ({ ...sessionMetadata });

//Fonction utilitaire pour header premium
export const setPremiumBypass = (token) => {
  api.defaults.headers.common['X-Rate-Limit-Bypass'] = token;
};

//Fonction pour nettoyer les metadata
export const clearSessionMetadata = () => {
  sessionMetadata = {
    scanProgress: null,
    remainingScans: null,
    securityScore: null,
    currentScanId: null
  };
};

export default api;