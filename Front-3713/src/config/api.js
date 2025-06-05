// src/config/api.js - Version JWT améliorée
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

// Intercepteur de requête amélioré pour JWT
api.interceptors.request.use(
  config => {
    const token = localStorage.getItem('token');
    if (token) {
      // Assurez-vous que les headers existent
      config.headers = config.headers || {};
      
      // 🔧 Force le header Authorization avec le Bearer token (même format qu'avant)
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  error => {
    console.error("Request interceptor error:", error);
    return Promise.reject(error);
  }
);

// 🔧 NOUVEAU : Intercepteur de réponse amélioré avec refresh automatique JWT
api.interceptors.response.use(
  response => response,
  async error => {
    const originalRequest = error.config;
    
    // Gérer les erreurs d'authentification (401)
    if (error.response && error.response.status === 401 && !originalRequest._retry) {
      
      if (isRefreshing) {
        // Si on est déjà en train de refresh, attendre
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
        // 🔧 Tenter un refresh du token
        const refreshResponse = await api.post('/refresh');
        const newToken = refreshResponse.data.access_token;
        
        // Sauvegarder le nouveau token
        localStorage.setItem('token', newToken);
        
        // Mettre à jour le header Authorization
        api.defaults.headers.common['Authorization'] = `Bearer ${newToken}`;
        originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
        
        processQueue(null, newToken);
        
        // Réessayer la requête originale
        return api(originalRequest);
        
      } catch (refreshError) {
        // Le refresh a échoué, déconnecter l'utilisateur
        processQueue(refreshError, null);
        
        // Nettoyer le localStorage
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        
        // Rediriger vers login (optionnel)
        console.warn("Token refresh failed, user needs to login again");
        
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }
    
    return Promise.reject(error);
  }
);

export default api;