// src/context/AuthContext.tsx - CORRECTION VÉRIFIÉE pour votre implémentation JWT
import React, { createContext, useState, useContext, useEffect, ReactNode } from 'react';
import axios from 'axios';

interface User {
  id: number;
  name: string;
  email: string;
  two_factor_enabled?: boolean;
}

interface AuthContextType {
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
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);

  // 2FA states
  const [twoFactorRequired, setTwoFactorRequiredState] = useState(false);
  const [pendingUserId, setPendingUserId] = useState<number | null>(null);
  const [pendingCredentials, setPendingCredentials] = useState<{ email: string; password: string } | null>(null);

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

  const setTwoFactorRequired = (
    required: boolean, 
    userId?: number, 
    credentials?: { email: string; password: string }
  ) => {
    setTwoFactorRequiredState(required);
    setPendingUserId(userId || null);
    setPendingCredentials(credentials || null);
  };

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

  const logout = () => {
    setUser(null);
    setToken(null);
    setIsAuthenticated(false);
    
    localStorage.removeItem('user');
    localStorage.removeItem('token');
    localStorage.removeItem('refresh_token'); // 🔧 Ajouté pour votre JWT
    
    // Clear 2FA state
    setTwoFactorRequiredState(false);
    setPendingUserId(null);
    setPendingCredentials(null);
  };

  // 🔧 CORRECTION CRITIQUE : Utiliser /auth/login (qui existe dans votre backend) 
  // avec two_factor_code au lieu de /auth/verify-2fa (qui n'existe pas)
  const submitTwoFactor = async (code: string) => {
    if (!pendingCredentials || !pendingUserId) {
      throw new Error('No pending 2FA authentication');
    }

    console.log('🔧 AuthContext: Submitting 2FA code via /auth/login');

    try {
      // 🔧 UTILISER VOTRE ROUTE EXISTANTE /auth/login avec two_factor_code
      // C'est exactement ce que votre AuthController::login() attend !
      const response = await axios.post('http://localhost:8000/api/auth/login', {
        email: pendingCredentials.email,
        password: pendingCredentials.password,
        two_factor_code: code, // Votre AuthController vérifie ce champ
      }, {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      });

      console.log('🔧 AuthContext: 2FA verification response:', response.data);

      const data = response.data;

      // 🔧 Votre JWT retourne access_token et refresh_token
      if (data.user && data.access_token) {
        // 🔧 SAUVEGARDER LE REFRESH_TOKEN (manquait dans votre code original)
        if (data.refresh_token) {
          localStorage.setItem('refresh_token', data.refresh_token);
        }
        
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

  const clearTwoFactor = () => {
    setTwoFactorRequiredState(false);
    setPendingUserId(null);
    setPendingCredentials(null);
  };

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