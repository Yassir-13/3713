// src/config/api.js - VERSION CORRIGÉE
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000/api',
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  }
});

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

// Intercepteur de requête
api.interceptors.request.use(
  config => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers = config.headers || {};
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  error => {
    console.error("Request interceptor error:", error);
    return Promise.reject(error);
  }
);

// 🔧 CORRECTION : Intercepteur de réponse avec bonne route refresh
api.interceptors.response.use(
  response => response,
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
        // 🔧 CORRECTION : Utiliser la bonne route /auth/refresh
        const refreshToken = localStorage.getItem('refresh_token');
        if (!refreshToken) {
          throw new Error('No refresh token available');
        }

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
        
        return api(originalRequest);
        
      } catch (refreshError) {
        processQueue(refreshError, null);
        
        // Nettoyer le localStorage
        localStorage.removeItem('token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
        
        console.warn("Token refresh failed, user needs to login again");
        
        // Rediriger vers login si possible
        if (window.location.pathname !== '/login') {
          window.location.href = '/login';
        }
        
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }
    
    return Promise.reject(error);
  }
);

export default api;