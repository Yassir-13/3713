// src/context/AuthContext.tsx - Version JWT corrigée
import React, { createContext, useState, useContext, useEffect, ReactNode } from 'react';
import axios from 'axios';

interface User {
  id: number;
  name: string;
  email: string;
  two_factor_enabled?: boolean;
}

interface AuthContextType {
  // Existing states
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  login: (user: User, token: string) => void;
  logout: () => void;
  
  // 2FA states
  twoFactorRequired: boolean;
  pendingUserId: number | null;
  pendingCredentials: { email: string; password: string } | null;
  
  // 2FA actions
  setTwoFactorRequired: (required: boolean, userId?: number, credentials?: { email: string; password: string }) => void;
  submitTwoFactor: (code: string) => Promise<void>;
  clearTwoFactor: () => void;
}

const defaultContext: AuthContextType = {
  user: null,
  token: null,
  isAuthenticated: false,
  login: () => {},
  logout: () => {},
  twoFactorRequired: false,
  pendingUserId: null,
  pendingCredentials: null,
  setTwoFactorRequired: () => {},
  submitTwoFactor: async () => {},
  clearTwoFactor: () => {},
};

const AuthContext = createContext<AuthContextType>(defaultContext);

export const useAuth = () => useContext(AuthContext);

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  // Existing states
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);

  // 2FA states
  const [twoFactorRequired, setTwoFactorRequiredState] = useState(false);
  const [pendingUserId, setPendingUserId] = useState<number | null>(null);
  const [pendingCredentials, setPendingCredentials] = useState<{ email: string; password: string } | null>(null);

  // Load from localStorage on startup
  useEffect(() => {
    try {
      const storedUser = localStorage.getItem('user');
      const storedToken = localStorage.getItem('token');
      
      if (storedUser && storedToken) {
        const userData = JSON.parse(storedUser);
        setUser(userData);
        setToken(storedToken);
        setIsAuthenticated(true);
      }
    } catch (e) {
      console.error('Error loading from storage:', e);
      localStorage.removeItem('user');
      localStorage.removeItem('token');
    }
    
    setLoading(false);
  }, []);

  // Set two-factor authentication required
  const setTwoFactorRequired = (
    required: boolean, 
    userId?: number, 
    credentials?: { email: string; password: string }
  ) => {
    setTwoFactorRequiredState(required);
    setPendingUserId(userId || null);
    setPendingCredentials(credentials || null);
  };

  // Login function - 🔧 Support JWT access_token
  const login = (userData: User, authToken: string) => {
    console.log('🔧 AuthContext: Logging in user with JWT token');
    setUser(userData);
    setToken(authToken);
    setIsAuthenticated(true);
    
    localStorage.setItem('user', JSON.stringify(userData));
    localStorage.setItem('token', authToken);
    
    // Clear 2FA state after successful login
    setTwoFactorRequiredState(false);
    setPendingUserId(null);
    setPendingCredentials(null);
  };

  // Logout function
  const logout = () => {
    setUser(null);
    setToken(null);
    setIsAuthenticated(false);
    
    localStorage.removeItem('user');
    localStorage.removeItem('token');
    
    // Clear 2FA state
    setTwoFactorRequiredState(false);
    setPendingUserId(null);
    setPendingCredentials(null);
  };

  // 🔧 CORRECTION CRITIQUE : Submit two-factor authentication code
  const submitTwoFactor = async (code: string) => {
    if (!pendingCredentials || !pendingUserId) {
      throw new Error('No pending 2FA authentication');
    }

    console.log('🔧 AuthContext: Submitting 2FA code for user:', pendingUserId);

    try {
      // 🔧 NOUVELLE APPROCHE : Utiliser axios directement SANS intercepteur
      // pour éviter d'envoyer un Bearer token qu'on n'a pas encore
      const response = await axios.post('http://localhost:8000/api/auth/verify-2fa', {
        user_id: pendingUserId,
        email: pendingCredentials.email,
        password: pendingCredentials.password,
        two_factor_code: code,
      }, {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
          // 🔧 PAS de Authorization header ici !
        }
      });

      console.log('🔧 AuthContext: 2FA verification response:', response.data);

      const data = response.data;

      // 🔧 JWT retourne access_token
      if (data.user && data.access_token) {
        login(data.user, data.access_token);
      } else {
        throw new Error('Invalid response from 2FA verification');
      }

    } catch (error: any) {
      console.error('🔧 AuthContext: 2FA verification error:', error);
      
      if (error.response?.data?.message) {
        throw new Error(error.response.data.message);
      } else {
        throw new Error('2FA verification failed');
      }
    }
  };

  // Clear two-factor authentication state
  const clearTwoFactor = () => {
    setTwoFactorRequiredState(false);
    setPendingUserId(null);
    setPendingCredentials(null);
  };

  // Context value
  const contextValue: AuthContextType = {
    user,
    token,
    isAuthenticated,
    login,
    logout,
    twoFactorRequired,
    pendingUserId,
    pendingCredentials,
    setTwoFactorRequired,
    submitTwoFactor,
    clearTwoFactor,
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
};

export { AuthContext };