// Front-3713/src/pages/Register.tsx - VERSION CORRIGÉE
import React, { useState, useContext } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';

const Register: React.FC = () => {
  const [form, setForm] = useState({
    name: '',
    email: '',
    password: '',
    password_confirmation: '',
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const apiUrl = 'http://localhost:8000/api/auth/register';
      console.log('🔧 DEBUG: API URL used:', apiUrl);
      console.log('🔧 DEBUG: Form data:', {
        name: form.name,
        email: form.email,
        password: '***hidden***'
      });

      const response = await axios.post(apiUrl, {
        name: form.name.trim(),
        email: form.email.trim(),
        password: form.password,
        password_confirmation: form.password_confirmation
      }, {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      });

      console.log('🔧 DEBUG: Response received:', {
        status: response.status,
        data: response.data,
        hasUser: !!response.data.user,
        hasAccessToken: !!response.data.access_token,
        hasRefreshToken: !!response.data.refresh_token
      });

      // 🔧 CORRECTION : Récupérer access_token ET refresh_token
      const { user, access_token, refresh_token } = response.data;
      
      if (user && access_token) {
        console.log('🔧 DEBUG: Calling login with JWT tokens');
        
        // 🔧 CORRECTION CRITIQUE : Sauvegarder le refresh_token
        if (refresh_token) {
          localStorage.setItem('refresh_token', refresh_token);
          console.log('🔧 DEBUG: Refresh token saved during registration');
        }
        
        login(user, access_token);
        navigate('/scanner');
      } else {
        console.error('🔧 DEBUG: Missing user or access_token in response');
        setError('Invalid response from server - missing authentication data');
      }
    } catch (err: any) {
      console.error('🔧 DEBUG: Registration error:', {
        message: err.message,
        response: err.response?.data,
        status: err.response?.status,
        headers: err.response?.headers
      });
      
      if (err.response?.data?.errors) {
        const errors = err.response.data.errors;
        const errorMessages = Object.values(errors).flat().join(', ');
        setError(`Validation errors: ${errorMessages}`);
      } else if (err.response?.data?.message) {
        setError(err.response.data.message);
      } else {
        setError(`Registration failed: ${err.message}`);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="d-flex justify-content-center align-items-center vh-100"
      style={{ backgroundColor: 'var(--bg-color)' }}
    >
      <div
        style={{
          marginTop: "2rem",
          padding: "1.5rem",
          border: "1px solid var(--accent-color)",
          borderRadius: "8px",
          boxShadow: "0 0 12px var(--accent-color)",
          backgroundColor: 'var(--bg-color)',
          color: "var(--text-color)",
          fontSize: "0.9rem",
          lineHeight: "1.6",
          maxWidth: "500px",
          minWidth: "400px",
          textAlign: "left",
        }}
      >
        <h2 className="text-center mb-4">Register</h2>

        {error && (
          <div className="alert alert-danger text-center mb-3">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="mb-3">
            <label>Name:</label>
            <input
              type="text"
              name="name"
              className="form-control"
              value={form.name}
              onChange={handleChange}
              required
              disabled={loading}
              minLength={2}
            />
          </div>

          <div className="mb-3">
            <label>Email:</label>
            <input
              type="email"
              name="email"
              className="form-control"
              value={form.email}
              onChange={handleChange}
              required
              disabled={loading}
            />
          </div>

          <div className="mb-3">
            <label>Password:</label>
            <input
              type="password"
              name="password"
              className="form-control"
              value={form.password}
              onChange={handleChange}
              required
              disabled={loading}
              minLength={8}
            />
          </div>

          <div className="mb-3">
            <label>Confirm Password:</label>
            <input
              type="password"
              name="password_confirmation"
              className="form-control"
              value={form.password_confirmation}
              onChange={handleChange}
              required
              disabled={loading}
              minLength={8}
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
            {loading ? 'Registering...' : 'Register'}
          </button>
        </form>

        <div className="text-center mt-3">
          <p>Already have an account? <a href="/login" style={{ color: 'var(--accent-color)' }}>Login here</a></p>
        </div>
      </div>
    </div>
  );
};

export default Register;