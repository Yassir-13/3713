// src/components/Footer.tsx
import React from 'react';

const Footer: React.FC = () => {
  return (
    <footer
      className="d-flex flex-column align-items-center justify-content-center py-4"
      style={{
        marginTop: '6rem',
        background: 'rgba(0, 0, 0, 0.4)',
        borderTop: '1px solid rgba(255, 255, 255, 0.1)',
        boxShadow: '0 -2px 12px hsl(0, 100.00%, 99.60%)',
        fontFamily: "'Orbitron', sans-serif",
        color: 'var(--accent-color)',
        textShadow: '0 0 8px var(--accent-color)',
      }}
    >
      <p className="text-center" style={{ fontSize: '1.2rem' }}>
        &copy; 2025 <strong>3713</strong> — Explore. Test. Secure.
      </p>
      <p
        className="text-center"
        style={{
          fontSize: '0.9rem',
          color: 'rgba(255, 255, 255, 0.6)',
          marginTop: '0.5rem',
        }}
      >
        Made with ❤️ by your cyber security sidekick
      </p>
    </footer>
  );
};

export default Footer;
