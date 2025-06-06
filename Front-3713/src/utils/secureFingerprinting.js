// src/utils/secureFingerprinting.js - Fingerprinting sécurisé pour 3713

class SecureFingerprinting {
  constructor() {
    this.cache = new Map();
  }

  // 🔒 Génération d'un fingerprint sécurisé et stable
  async generateSecureFingerprint() {
    const cacheKey = 'secure_fingerprint';
    
    // Vérifier le cache persistant
    const cached = localStorage.getItem(cacheKey);
    if (cached) {
      try {
        const parsed = JSON.parse(cached);
        if (this.isValidFingerprint(parsed)) {
          return parsed.id;
        }
      } catch (e) {
        console.warn('Invalid cached fingerprint, regenerating...');
      }
    }

    // Générer nouveau fingerprint
    const fingerprint = await this.generateFingerprint();
    
    // Sauvegarder en cache
    const fingerprintData = {
      id: fingerprint,
      generated: Date.now(),
      version: '3713-v1'
    };
    
    localStorage.setItem(cacheKey, JSON.stringify(fingerprintData));
    
    return fingerprint;
  }

  // 🔒 Validation du fingerprint
  isValidFingerprint(data) {
    return data && 
           data.id && 
           data.generated && 
           data.version === '3713-v1' &&
           (Date.now() - data.generated) < 30 * 24 * 60 * 60 * 1000; // 30 jours
  }

  // 🔒 Génération du fingerprint avec méthodes multiples
  async generateFingerprint() {
    const components = [];

    // 1. Canvas fingerprinting sécurisé
    components.push(await this.getCanvasFingerprint());

    // 2. WebGL fingerprinting
    components.push(this.getWebGLFingerprint());

    // 3. Propriétés du navigateur (stables)
    components.push(this.getBrowserFingerprint());

    // 4. Propriétés de l'écran
    components.push(this.getScreenFingerprint());

    // 5. Timezone et langue
    components.push(this.getLocaleFingerprint());

    // 6. Fonctionnalités supportées
    components.push(await this.getFeaturesFingerprint());

    // Combiner et hasher
    const combined = components.join('|');
    const hash = await this.hashString(combined);
    
    return `3713_${hash.substring(0, 16)}`;
  }

  // 🔒 Canvas fingerprinting avancé
  async getCanvasFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      
      canvas.width = 280;
      canvas.height = 60;
      
      // Texte avec emoji et caractères spéciaux
      ctx.textBaseline = 'alphabetic';
      ctx.fillStyle = '#4c4c4c';
      ctx.font = '14px "Arial", sans-serif';
      ctx.fillText('3713 Security Scanner 🔒', 2, 15);
      
      // Forme géométrique
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillRect(100, 20, 80, 20);
      
      // Dégradé
      const gradient = ctx.createLinearGradient(0, 0, 180, 0);
      gradient.addColorStop(0, '#ff0000');
      gradient.addColorStop(1, '#0000ff');
      ctx.fillStyle = gradient;
      ctx.fillRect(0, 40, 180, 20);
      
      return canvas.toDataURL();
    } catch (e) {
      return 'canvas_error';
    }
  }

  // 🔒 WebGL fingerprinting
  getWebGLFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      
      if (!gl) return 'no_webgl';
      
      const info = {
        vendor: gl.getParameter(gl.VENDOR),
        renderer: gl.getParameter(gl.RENDERER),
        version: gl.getParameter(gl.VERSION),
        shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS)
      };
      
      return JSON.stringify(info);
    } catch (e) {
      return 'webgl_error';
    }
  }

  // 🔒 Propriétés navigateur stables
  getBrowserFingerprint() {
    const nav = navigator;
    return [
      nav.userAgent,
      nav.language,
      nav.languages ? nav.languages.join(',') : '',
      nav.platform,
      nav.cookieEnabled,
      nav.doNotTrack,
      nav.maxTouchPoints || 0,
      nav.hardwareConcurrency || 0
    ].join('|');
  }

  // 🔒 Propriétés écran
  getScreenFingerprint() {
    const screen = window.screen;
    return [
      screen.width,
      screen.height,
      screen.availWidth,
      screen.availHeight,
      screen.colorDepth,
      screen.pixelDepth,
      window.devicePixelRatio || 1
    ].join('|');
  }

  // 🔒 Locale et timezone
  getLocaleFingerprint() {
    return [
      Intl.DateTimeFormat().resolvedOptions().timeZone,
      new Date().getTimezoneOffset(),
      Intl.DateTimeFormat().resolvedOptions().locale,
      Intl.NumberFormat().resolvedOptions().locale
    ].join('|');
  }

  // 🔒 Fonctionnalités supportées
  async getFeaturesFingerprint() {
    const features = [];
    
    // APIs disponibles
    features.push('webgl' + (!!window.WebGLRenderingContext));
    features.push('indexeddb' + (!!window.indexedDB));
    features.push('localstorage' + (!!window.localStorage));
    features.push('sessionstorage' + (!!window.sessionStorage));
    features.push('webworkers' + (!!window.Worker));
    features.push('notifications' + (!!window.Notification));
    
    // Permissions API
    if (navigator.permissions) {
      try {
        const permission = await navigator.permissions.query({name: 'notifications'});
        features.push('notif_perm' + permission.state);
      } catch (e) {
        features.push('notif_perm_error');
      }
    }
    
    return features.join('|');
  }

  // 🔒 Hash SHA-256 natif
  async hashString(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // 🔒 Validation côté client
  validateFingerprint(fingerprint) {
    return fingerprint && 
           typeof fingerprint === 'string' &&
           fingerprint.startsWith('3713_') &&
           fingerprint.length === 21 &&
           /^3713_[a-f0-9]{16}$/.test(fingerprint);
  }
}

// Instance singleton
const secureFingerprinting = new SecureFingerprinting();

// Export pour utilisation dans api.js
export default secureFingerprinting;