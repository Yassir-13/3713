// src/components/CTASection.tsx
import React from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';



const CTASection: React.FC = () => {
  const { user } = useAuth(); 
const navigate = useNavigate(); 
  return (
    <section
      className="cta d-flex flex-column align-items-center justify-content-center p-4"
      style={{
        border: '2px solid var(--border-color)',
        borderRadius: '10px',
        boxShadow: '0 0 10px var(--border-color)',
        transition: 'border-color 0.3s, box-shadow 0.3s',
      }}
    >
      <h2
        style={{
          color: 'var(--text-color)',
          fontSize: '3rem',
          marginBottom: '2rem',
        }}
      >
        Are you ready?
      </h2>

      <button
          className="cta-btn"
          onClick={() => {
            if (!user) {
              navigate('/login');
            } else {
              navigate('/scanner');
            }
          }}
          style={{
            padding: '1rem 2rem',
            fontSize: '1.25rem',
            backgroundColor: 'var(--accent-color)',
            color: 'var(--bg-color)',
            border: 'none',
            borderRadius: '5px',
            cursor: 'pointer',
            transition: 'background-color 0.3s, transform 0.3s',
          }}
        >
          START
        </button>
      </section>
  );
};

export default CTASection;
