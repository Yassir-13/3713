import React, { useState, useContext, useEffect } from 'react';
import axios from 'axios';
import { AuthContext } from '../context/AuthContext';
import { useNavigate, useLocation } from 'react-router-dom';
import '../App.css';

// Interface pour le state de localisation
interface LocationState {
  from?: {
    pathname: string;
  };
}

const Login: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const { login, isAuthenticated } = useContext(AuthContext);
  const navigate = useNavigate();
  const location = useLocation();
  
  // Vérifier si l'utilisateur est déjà connecté
  useEffect(() => {
    if (isAuthenticated) {
      // Si l'utilisateur est déjà connecté, rediriger vers la page scanner
      navigate('/scanner');
    }
  }, [isAuthenticated, navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await axios.post('http://localhost:8000/api/login', {
        email,
        password,
      });

      const { user, token } = response.data;
      
      // Utiliser la fonction login du contexte
      login(user, token);
      
      // Rediriger vers la page d'origine ou vers scanner
      const state = location.state as LocationState;
      const redirectPath = state?.from?.pathname || '/scanner';
      navigate(redirectPath);
      
    } catch (err: any) {
      setError('Invalid credentials or server error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="d-flex justify-content-center align-items-center vh-100"
      style={{
        backgroundColor: 'var(--bg-color)',
        transition: 'background-color 0.3s ease',
      }}
    >
      <div
        style={{
          marginTop: "2rem",
          padding: "1.5rem",
          border: "1px solid var(--accent-color)",
          borderRadius: "8px",
          boxShadow: "0 0 12px var(--accent-color)",
          backgroundColor:'var(--bg-color)',
          color: "var(--text-color)",
          fontSize: "0.9rem",
          lineHeight: "1.6",
          maxWidth: "800px",
          textAlign: "left",
        }}
      >
        <h2 className="text-center mb-4">Login</h2>

        {error && <p className="text-danger text-center">{error}</p>}

        <form onSubmit={handleSubmit}>
          <div className="mb-3">
            <label>Email:</label>
            <input
              type="email"
              className="form-control"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          <div className="mb-3">
            <label>Password:</label>
            <input
              type="password"
              className="form-control"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          <button  
            type="submit"
            className="btn w-100"
            style={{
              backgroundColor: 'var(--border-color)',
              color: 'var(--bg-color)',
              border: '1px solid var(--border-color)',
            }}
            disabled={loading}
          >
            {loading ? 'Logging in...' : 'Log in'}
          </button>
        </form>
      </div>
    </div>
  );
};

export default Login;