// src/components/AboutSection.tsx
import React from 'react';

interface AboutProps {
  title: string;
  text: string;
  image: string;
}

const AboutSection: React.FC<AboutProps> = ({ title, text, image }) => {
  return (
    <section className="about-reveal">
      <div
        className="about-box d-flex flex-column align-items-center justify-content-center p-4"
        style={{
          border: '2px solid var(--border-color)',
          borderRadius: '10px',
          boxShadow: '0 0 10px var(--border-color)',
          transition: 'border-color 0.3s, box-shadow 0.3s',
        }}
      >
        <div className="about-content d-flex flex-column flex-md-row align-items-center justify-content-center gap-4">
          <div className="text text-center text-md-start">
            <h2 style={{ color: 'var(--text-color)' }}>{title}</h2>
            <p style={{ color: 'var(--text-color)' }}>{text}</p>
          </div>
          <div className="image-container">
            <img src={image} alt="About Image" className="about-img" style={{ width: '300px', height: '300px', borderRadius: '10px' }} />
          </div>
        </div>
      </div>
    </section>
  );
};

export default AboutSection;
