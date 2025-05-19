// src/pages/HomePage.tsx
import React from 'react';
import Header from '../components/Header';
import HeroSection from '../components/HeroSection';
import AboutSection from '../components/AboutSection';
import CTASection from '../components/CTASection';
import Footer from '../components/Footer';
import RevealEffect from '../components/RevealEffects';


const HomePage: React.FC = () => {
  return (
    <div className="">
      <Header />
      <HeroSection />
      <AboutSection 
        title="Why 3713?" 
        text="We make security testing easy and accessible for everyone. Whether you’re just starting out or launching the next big thing, our tools are designed to support your journey — no fluff, just results!" 
        image="./public/pic-1-3413.jpg"
      />
      <AboutSection 
        title="What can 3713 do?" 
        text="3713 can perform a full and deep scan of the application you asked us to analyze. We search for every potential risk that can be found in your favorite apps. We will handle everything for you, including the security report!" 
        image="./public/pic-2-3713.jpg"
      />
      <CTASection />
      <Footer />
      <RevealEffect />
    </div>
  );
};

export default HomePage;
