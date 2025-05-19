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
  const { login } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    try {
      const res = await axios.post('http://localhost:8000/api/register', form);
      const { user, token } = res.data;
      login(user, token);
      navigate('/');
    } catch (err: any) {
      setError('Registration failed. Please check your input.');
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
            backgroundColor:'var(--bg-color)',
            color: "var(--text-color)",
            fontSize: "0.9rem",
            lineHeight: "1.6",
            maxWidth: "800px",
            textAlign: "left",
        }}
      >
        <h2 className="text-center mb-4">Register</h2>

        {error && <p className="text-danger text-center">{error}</p>}

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
            >
            Register
            </button>
        </form>
      </div>
    </div>
  );
};

export default Register;
