// src/context/AuthContext.tsx - Version Finale Propre
import React, { createContext, useState, useContext, useEffect, ReactNode } from 'react';

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

  // Login function
  const login = (userData: User, authToken: string) => {
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

  // Submit two-factor authentication code
  const submitTwoFactor = async (code: string) => {
    if (!pendingCredentials || !pendingUserId) {
      throw new Error('No pending 2FA authentication');
    }

    try {
      const response = await fetch('http://localhost:8000/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          email: pendingCredentials.email,
          password: pendingCredentials.password,
          two_factor_code: code,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || '2FA verification failed');
      }

      if (data.user && data.token) {
        login(data.user, data.token);
      } else {
        throw new Error('Invalid response from server');
      }

    } catch (error) {
      throw error;
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