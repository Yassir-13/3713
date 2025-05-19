// src/context/AuthContext.tsx
import React, { createContext, useState, useContext, useEffect, ReactNode } from 'react';

interface User {
  id: number;
  name: string;
  email: string;
  // Ajoutez d'autres propriétés utilisateur si nécessaire
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  login: (user: User, token: string) => void;
  logout: () => void;
}

// Valeur par défaut du contexte
const defaultContext: AuthContextType = {
  user: null,
  token: null,
  isAuthenticated: false,
  login: () => {},
  logout: () => {},
};

// Créer le contexte
const AuthContext = createContext<AuthContextType>(defaultContext);

// Hook personnalisé pour utiliser le contexte
export const useAuth = () => useContext(AuthContext);

interface AuthProviderProps {
  children: ReactNode;
}

// Provider du contexte
export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);

  // Charger l'utilisateur et le token depuis localStorage au démarrage
  useEffect(() => {
    const storedUser = localStorage.getItem('user');
    const storedToken = localStorage.getItem('token');
    
    if (storedUser && storedToken) {
      setUser(JSON.parse(storedUser));
      setToken(storedToken);
      setIsAuthenticated(true);
    }
    
    setLoading(false);
  }, []);

  // Fonction de connexion
  const login = (userData: User, authToken: string) => {
    setUser(userData);
    setToken(authToken);
    setIsAuthenticated(true);
    
    // Stocker les données dans localStorage
    localStorage.setItem('user', JSON.stringify(userData));
    localStorage.setItem('token', authToken);
  };

  // Fonction de déconnexion
  const logout = () => {
    setUser(null);
    setToken(null);
    setIsAuthenticated(false);
    
    // Supprimer les données de localStorage
    localStorage.removeItem('user');
    localStorage.removeItem('token');
  };

  // Valeur fournie par le contexte
  const value = {
    user,
    token,
    isAuthenticated,
    login,
    logout,
  };

  // Ne render les enfants que lorsque le chargement initial est terminé
  if (loading) {
    return <div>Chargement...</div>; // Ou un spinner, ou rien du tout
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export { AuthContext };