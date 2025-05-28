// src/pages/Settings.tsx
// ⚙️ Page Settings principale avec section A2F
import React, { useState } from 'react';
import AppLayout from '../components/layout';
import TwoFactorSettings from '../components/TwoFactorSettings';

type SettingsTab = 'security' | 'profile' | 'preferences';

const Settings: React.FC = () => {
  const [activeTab, setActiveTab] = useState<SettingsTab>('security');

  const tabs = [
    { id: 'security' as SettingsTab, label: 'Security', icon: '🔐' },
    { id: 'profile' as SettingsTab, label: 'Profile', icon: '👤' },
    { id: 'preferences' as SettingsTab, label: 'Preferences', icon: '⚙️' },
  ];

  return (
    <AppLayout>
      <div style={styles.container}>
        <div style={styles.header}>
          <h2 style={styles.title}>Settings</h2>
          <p style={styles.subtitle}>Manage your account settings and preferences</p>
        </div>

        {/* Navigation des onglets */}
        <div style={styles.tabsContainer}>
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                ...styles.tab,
                ...(activeTab === tab.id ? styles.activeTab : styles.inactiveTab)
              }}
            >
              <span style={styles.tabIcon}>{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </div>

        {/* Contenu des onglets */}
        <div style={styles.tabContent}>
          {activeTab === 'security' && (
            <div style={styles.section}>
              <h3 style={styles.sectionTitle}>Security Settings</h3>
              <p style={styles.sectionDescription}>
                Manage your account security and two-factor authentication
              </p>
              
              {/* Composant A2F */}
              <TwoFactorSettings />
            </div>
          )}

          {activeTab === 'profile' && (
            <div style={styles.section}>
              <h3 style={styles.sectionTitle}>Profile Settings</h3>
              <p style={styles.sectionDescription}>
                Update your profile information and preferences
              </p>
              
              <div style={styles.comingSoon}>
                <span style={styles.comingSoonIcon}>🚧</span>
                <p>Profile settings coming soon...</p>
              </div>
            </div>
          )}

          {activeTab === 'preferences' && (
            <div style={styles.section}>
              <h3 style={styles.sectionTitle}>Preferences</h3>
              <p style={styles.sectionDescription}>
                Customize your application experience
              </p>
              
              <div style={styles.comingSoon}>
                <span style={styles.comingSoonIcon}>🚧</span>
                <p>Preferences settings coming soon...</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
};

const styles = {
  container: {
    padding: '2rem',
    color: 'var(--text-color)',
    width: '100%',
    maxWidth: '1000px',
    margin: '0 auto',
  },
  header: {
    marginBottom: '2rem',
    textAlign: 'center' as const,
  },
  title: {
    fontSize: '2.5rem',
    fontWeight: 'bold',
    marginBottom: '0.5rem',
    color: 'var(--text-color)',
  },
  subtitle: {
    fontSize: '1rem',
    opacity: 0.8,
    margin: 0,
  },
  tabsContainer: {
    display: 'flex',
    borderBottom: '2px solid var(--accent-color)',
    marginBottom: '2rem',
    gap: '0.5rem',
  },
  tab: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    padding: '0.75rem 1.5rem',
    border: 'none',
    background: 'transparent',
    cursor: 'pointer',
    fontSize: '1rem',
    fontFamily: 'inherit',
    transition: 'all 0.3s ease',
    borderRadius: '8px 8px 0 0',
  },
  activeTab: {
    backgroundColor: 'var(--accent-color)',
    color: 'var(--bg-color)',
    fontWeight: 'bold',
  },
  inactiveTab: {
    color: 'var(--text-color)',
    opacity: 0.7,
  },
  tabIcon: {
    fontSize: '1.2rem',
  },
  tabContent: {
    minHeight: '400px',
  },
  section: {
    marginBottom: '2rem',
  },
  sectionTitle: {
    fontSize: '1.5rem',
    fontWeight: 'bold',
    marginBottom: '0.5rem',
    color: 'var(--text-color)',
  },
  sectionDescription: {
    fontSize: '0.95rem',
    opacity: 0.8,
    marginBottom: '1.5rem',
  },
  comingSoon: {
    textAlign: 'center' as const,
    padding: '3rem',
    opacity: 0.6,
  },
  comingSoonIcon: {
    fontSize: '3rem',
    display: 'block',
    marginBottom: '1rem',
  },
};

export default Settings;