// src/components/RevealEffect.tsx
import React, { useEffect } from 'react';

const RevealEffect: React.FC = () => {
  useEffect(() => {
    const reveals = document.querySelectorAll('.reveal');
    const appearOnScroll = () => {
      reveals.forEach((section: any) => {
        const sectionTop = section.getBoundingClientRect().top;
        const windowHeight = window.innerHeight;

        if (sectionTop < windowHeight - 100) {
          section.classList.add('active');
        }
      });
    };

    window.addEventListener('scroll', appearOnScroll);
    window.addEventListener('load', appearOnScroll);

    return () => {
      window.removeEventListener('scroll', appearOnScroll);
      window.removeEventListener('load', appearOnScroll);
    };
  }, []);

  return null;
};

export default RevealEffect;
