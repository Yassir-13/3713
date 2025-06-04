// src/components/HeroSection.tsx
import React from 'react';

const HeroSection: React.FC = () => {
  return (
    <main
      className="d-flex flex-column align-items-center justify-content-center p-4"
      style={{
        height: '100vh',
        boxSizing: 'border-box',
      }}
    >
      <h1
        className="text-center"
        style={{
          fontSize: '7rem',
          textShadow: '0 0 16px var(--accent-color)', 
          color: 'var(--text-color)',
        }}
      >
        3713
      </h1>

      <div
        style={{
          width: '50%',
          height: '2px',
          backgroundColor: 'var(--accent-color)',
          marginBottom: '1rem',
        }}
      ></div>

      <p
        className="text-center"
        style={{
          fontSize: '1.25rem',
          maxWidth: '1000px',
          color: 'var(--text-color)',
        }}
      >
        Not sure how to test the security of your favorite app — or even your own creation? You’re not alone. Security testing can be tricky, but that’s exactly why we’re here. Whether you're a curious beginner or a passionate developer, we’ve got your back to help you uncover vulnerabilities before anyone else does — <i>and trust us, you’ll want to be the first to find them.</i>
      </p>

      <div
        style={{
          width: '50%',
          height: '2px',
          backgroundColor: 'var(--accent-color)', 
          marginTop: '1rem',
        }}
      ></div>
    </main>
  );
};

export default HeroSection;
