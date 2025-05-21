import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000/api',
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  }
});

// Intercepteur de requête amélioré
api.interceptors.request.use(
  config => {
    const token = localStorage.getItem('token');
    if (token) {
      // Assurez-vous que les headers existent
      config.headers = config.headers || {};
      
      // Force le header Authorization avec le Bearer token
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  error => {
    console.error("Request interceptor error:", error);
    return Promise.reject(error);
  }
);

// Intercepteur de réponse pour gérer les erreurs d'authentification
api.interceptors.response.use(
  response => response,
  error => {
    // Gérer les erreurs d'authentification (401)
    if (error.response && error.response.status === 401) {
      // Option: on pourrait rediriger vers login, mais dans ce cas
      // je préfère laisser le composant décider de la redirection
      console.warn("Authentication error detected");
    }
    return Promise.reject(error);
  }
);

export default api;