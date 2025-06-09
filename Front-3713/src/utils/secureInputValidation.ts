// src/utils/secureInputValidation.ts - Validation côté client compatible 3713

interface ValidationResult {
  isValid: boolean;
  sanitized?: string;
  errors: string[];
}

interface LoginFormData {
  email: string;
  password: string;
  two_factor_code?: string;
}

interface RegistrationFormData {
  name: string;
  email: string;
  password: string;
  password_confirmation: string;
}

interface FormValidationResult {
  isValid: boolean;
  sanitizedData: any;
  fieldResults: Record<string, ValidationResult>;
  errors: string[];
}

interface RateLimitResult {
  allowed: boolean;
  timeRemaining?: number;
  attemptsRemaining?: number;
  message: string;
}

class SecureInputValidator {
  private patterns: Record<string, RegExp>;
  private dangerousChars: RegExp;
  private injectionPatterns: RegExp[];

  constructor() {
    this.patterns = {
      name: /^[\p{L}\s.'-]{2,50}$/u,
      email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
      password: /^.{8,255}$/, 
      twoFactorCode: /^[0-9A-Z]{6,8}$/
    };

    // Caractères dangereux à filtrer
    this.dangerousChars = /[<>'"&\r\n\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;
    
    // Payloads d'injection courants
    this.injectionPatterns = [
      /script\s*:/i,              // Protocole javascript:
        /javascript\s*:/i,          // Protocole javascript: explicite
        /vbscript\s*:/i,           // VBScript (IE legacy)
        /onload\s*=/i,             // Event handler onload
        /onerror\s*=/i,            // Event handler onerror
        /onclick\s*=/i,            // Event handler onclick
        /onmouseover\s*=/i,        // Event handler onmouseover
        /eval\s*\(/i,              // Fonction eval() JavaScript
        /expression\s*\(/i,        // CSS expression() (IE)
        
        // === CATÉGORIE XSS BALISES HTML ===
        /<\s*script/i,             // Balise <script>
        /<\s*iframe/i,             // Balise <iframe>
        /<\s*object/i,             // Balise <object>
        /<\s*embed/i,              // Balise <embed>
        /<\s*form/i,               // Balise <form>
        /<\s*input/i,              // Balise <input>
        /<\s*meta/i,               // Balise <meta>
        /<\s*link/i,               // Balise <link>
        
        // === CATÉGORIE TEMPLATE INJECTION ===
        /\$\{/,                    // Template literals ${...}
        /\{\{.*\}\}/,              // Handlebars/Angular {{...}}
        /<%.*%>/,                  // ASP/JSP <% ... %>
        /\[\[.*\]\]/,              // Double bracket templates
        
        // === CATÉGORIE SQL INJECTION ===
        /union\s+select/i,         // UNION SELECT classique
        /drop\s+table/i,           // DROP TABLE destructeur
        /insert\s+into/i,          // INSERT INTO
        /delete\s+from/i,          // DELETE FROM
        /update\s+set/i,           // UPDATE SET
        /alter\s+table/i,          // ALTER TABLE
        /create\s+table/i,         // CREATE TABLE
        /truncate\s+table/i,       // TRUNCATE TABLE
        
        // === CATÉGORIE COMMAND INJECTION ===
        /;\s*rm\s/i,               // Command rm (Unix)
        /;\s*del\s/i,              // Command del (Windows)
        /;\s*cat\s/i,              // Command cat
        /;\s*wget\s/i,             // Command wget
        /;\s*curl\s/i,             // Command curl
        /;\s*nc\s/i,               // Netcat
        /\|\s*nc\s/i,              // Pipe vers netcat
        
        // === CATÉGORIE PATH TRAVERSAL ===
        /\.\.\//,                  // Directory traversal ../
        /\/etc\/passwd/i,          // Fichier passwd Unix
        /\/proc\/version/i,        // Fichier proc Linux
        /c:\\windows\\system32/i,  // Répertoire Windows
        
        // === CATÉGORIE LDAP INJECTION ===
        /\(\|\(/,                  // LDAP OR condition
        /\)\(\&\(/,                // LDAP AND condition
        /\*\)\(/,                  // LDAP wildcard
        
        // === CATÉGORIE XXE (XML EXTERNAL ENTITY) ===
        /<!ENTITY/i,               // Entity XML
        /<!DOCTYPE.*ENTITY/i,      // DOCTYPE avec ENTITY
        /SYSTEM\s+["']/i,          // SYSTEM declaration
        
        // === CATÉGORIE NOSQL INJECTION ===
        /\$ne\s*:/i,               // MongoDB $ne
        /\$gt\s*:/i,               // MongoDB $gt
        /\$where\s*:/i,            // MongoDB $where
        /\$regex\s*:/i,            // MongoDB $regex
    ];
  }

  /**
   * 🔒 Sanitisation ultra-stricte d'une chaîne
   */
  sanitizeString(input: string): string {
    if (typeof input !== 'string') {
      return '';
    }

    let sanitized = input;

    // 1. Suppression caractères de contrôle et dangereux
    sanitized = sanitized.replace(this.dangerousChars, '');

    // 2. Normalisation Unicode
    if (typeof sanitized.normalize === 'function') {
      sanitized = sanitized.normalize('NFC');
    }

    // 3. Trim et limitation de longueur
    sanitized = sanitized.trim().substring(0, 1000);

    // 4. Protection contre l'injection de code
    for (const pattern of this.injectionPatterns) {
      if (pattern.test(sanitized)) {
        console.warn('🚨 Potential injection attempt detected:', sanitized.substring(0, 50));
        return '';
      }
    }

    return sanitized;
  }

  /**
   * 🔒 Validation stricte du nom
   */
  validateName(name: string): ValidationResult {
    const sanitized = this.sanitizeString(name);
    
    const errors: string[] = [];

    if (!sanitized) {
      errors.push('Name is required');
      return { isValid: false, sanitized: '', errors };
    }

    if (sanitized.length < 2) {
      errors.push('Name must be at least 2 characters');
    }

    if (sanitized.length > 50) {
      errors.push('Name must not exceed 50 characters');
    }

    if (!this.patterns.name.test(sanitized)) {
      errors.push('Name can only contain letters, spaces, hyphens, dots, and apostrophes');
    }

    // Vérification caractères répétés (spam)
    if (/(.)\1{4,}/.test(sanitized)) {
      errors.push('Name contains too many repeated characters');
    }

    return {
      isValid: errors.length === 0,
      sanitized,
      errors
    };
  }

  /**
   * 🔒 Validation stricte de l'email - COMPATIBLE 3713
   */
  validateEmail(email: string): ValidationResult {
    const sanitized = this.sanitizeString(email).toLowerCase();
    
    const errors: string[] = [];

    if (!sanitized) {
      errors.push('Email is required');
      return { isValid: false, sanitized: '', errors };
    }

    if (sanitized.length > 100) {
      errors.push('Email must not exceed 100 characters');
    }

    // 🔧 CORRECTION : Pattern moins strict pour compatibilité
    if (!this.patterns.email.test(sanitized)) {
      errors.push('Please provide a valid email address');
    }

    return {
      isValid: errors.length === 0,
      sanitized,
      errors
    };
  }

  /**
   * 🔒 Validation mot de passe - COMPATIBLE 3713
   */
  validatePassword(password: string): ValidationResult {
    // ⚠️ NE PAS sanitiser les mots de passe
    const errors: string[] = [];

    if (!password) {
      errors.push('Password is required');
      return { isValid: false, errors };
    }

    if (password.length < 8) {
      errors.push('Password must be at least 8 characters');
    }

    if (password.length > 255) {
      errors.push('Password must not exceed 255 characters');
    }

    // 🔧 CORRECTION : Validation moins stricte pour compatibilité utilisateurs existants
    if (!this.patterns.password.test(password)) {
      errors.push('Password must be between 8 and 255 characters');
    }

    // Vérification caractères répétés
    if (/(.)\1{5,}/.test(password)) {
      errors.push('Password cannot contain more than 5 consecutive identical characters');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * 🔒 Validation code 2FA
   */
  validateTwoFactorCode(code: string): ValidationResult {
    const sanitized = this.sanitizeString(code).toUpperCase().replace(/\s/g, '');
    
    const errors: string[] = [];

    if (!sanitized) {
      return { isValid: true, sanitized: '', errors }; // Optionnel
    }

    if (!this.patterns.twoFactorCode.test(sanitized)) {
      errors.push('2FA code must be 6 digits (from app) or 8 characters (recovery code)');
    }

    return {
      isValid: errors.length === 0,
      sanitized,
      errors
    };
  }

  /**
   * 🔒 Validation complète du formulaire de login - COMPATIBLE 3713
   */
  validateLoginForm(formData: LoginFormData): FormValidationResult {
    const results = {
      email: this.validateEmail(formData.email),
      password: this.validatePassword(formData.password),
      two_factor_code: this.validateTwoFactorCode(formData.two_factor_code || '')
    };

    const isFormValid = results.email.isValid && 
                       results.password.isValid && 
                       results.two_factor_code.isValid;
    
    const sanitizedData: any = {
      email: results.email.sanitized,
      password: formData.password, // Ne pas sanitiser
      two_factor_code: results.two_factor_code.sanitized
    };

    // 🔧 CORRECTION : Supprimer two_factor_code si vide pour compatibilité backend
    if (!sanitizedData.two_factor_code) {
      delete sanitizedData.two_factor_code;
    }

    const allErrors = Object.values(results).reduce((acc: string[], field) => {
      return acc.concat(field.errors);
    }, []);

    return {
      isValid: isFormValid,
      sanitizedData,
      fieldResults: results,
      errors: allErrors
    };
  }

  /**
   * 🔒 Validation complète du formulaire d'inscription - COMPATIBLE 3713
   */
  validateRegistrationForm(formData: RegistrationFormData): FormValidationResult {
    const results = {
      name: this.validateName(formData.name),
      email: this.validateEmail(formData.email),
      password: this.validatePassword(formData.password),
      password_confirmation: this.validatePassword(formData.password_confirmation)
    };

    // Vérification que les mots de passe correspondent
    if (formData.password !== formData.password_confirmation) {
      results.password_confirmation.errors.push('Passwords do not match');
      results.password_confirmation.isValid = false;
    }

    const isFormValid = Object.values(results).every(field => field.isValid);
    
    const sanitizedData = {
      name: results.name.sanitized,
      email: results.email.sanitized,
      password: formData.password, // Ne pas sanitiser
      password_confirmation: formData.password_confirmation // Ne pas sanitiser
    };

    const allErrors = Object.values(results).reduce((acc: string[], field) => {
      return acc.concat(field.errors);
    }, []);

    return {
      isValid: isFormValid,
      sanitizedData,
      fieldResults: results,
      errors: allErrors
    };
  }

  /**
   * 🔒 Validation header HTTP sécurisée - COMPATIBLE 3713
   */
  validateHeaders(headers: Record<string, string>): Record<string, string> {
    const sanitizedHeaders: Record<string, string> = {};
    
    for (const [key, value] of Object.entries(headers)) {
      // Validation nom header
      if (!/^[a-zA-Z0-9\-_]+$/.test(key)) {
        console.warn('🚨 Invalid header name:', key);
        continue;
      }

      // Sanitisation valeur header
      const sanitizedValue = this.sanitizeString(value);
      
      // Validation longueur
      if (sanitizedValue.length > 1000) {
        console.warn('🚨 Header value too long:', key);
        continue;
      }

      sanitizedHeaders[key] = sanitizedValue;
    }

    return sanitizedHeaders;
  }

  /**
   * 🔒 Détection tentatives d'injection avancées
   */
  detectAdvancedInjection(input: string): boolean {
    const suspiciousPatterns = [
      // SQL Injection
      /(\bUNION\b|\bSELECT\b|\bINSERT\b|\bDELETE\b|\bDROP\b|\bEXEC\b)/i,
      
      // XSS
      /<script[\s\S]*?>[\s\S]*?<\/script>/i,
      /javascript\s*:/i,
      /on\w+\s*=/i,
      
      // Command Injection
      /[;&|`$(){}[\]]/,
      
      // Path Traversal
      /\.\.\//,
      
      // LDAP Injection
      /[*()\\]/,
      
      // XXE
      /<!ENTITY/i,
      
      // Template Injection
      /\{\{.*\}\}/,
      /\$\{.*\}/,
      /<.*%>/
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(input)) {
        return true;
      }
    }

    return false;
  }

  /**
   * 🔧 NOUVEAU : Méthode dummy pour compatibilité (JWT n'a pas besoin de CSRF)
   */
  generateCSRFToken(): string {
    console.log('🔧 CSRF token not needed with JWT - returning dummy token');
    return 'jwt-no-csrf-needed';
  }

  /**
   * 🔒 Validation d'URL sécurisée
   */
  validateUrl(url: string): ValidationResult {
    const sanitized = this.sanitizeString(url);
    const errors: string[] = [];

    if (!sanitized) {
      errors.push('URL is required');
      return { isValid: false, sanitized: '', errors };
    }

    if (sanitized.length > 2048) {
      errors.push('URL must not exceed 2048 characters');
    }

    // Pattern URL basique
    const urlPattern = /^https?:\/\/[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?(?:\/[^\s]*)?$/;
    if (!urlPattern.test(sanitized)) {
      errors.push('Please provide a valid URL (http:// or https://)');
    }

    // Vérification domaines dangereux
    try {
      const dangerousDomains = ['localhost', 'internal', 'admin', '127.0.0.1', '0.0.0.0'];
      const urlObj = new URL(sanitized);
      
      for (const domain of dangerousDomains) {
        if (urlObj.hostname.includes(domain)) {
          errors.push('This domain is not allowed for security reasons');
          break;
        }
      }
    } catch (e) {
      errors.push('Invalid URL format');
    }

    return {
      isValid: errors.length === 0,
      sanitized,
      errors
    };
  }

  /**
   * 🔒 Rate limiting côté client (protection brute force)
   */
  checkRateLimit(action: string, maxAttempts: number = 5, windowMs: number = 300000): RateLimitResult {
    const key = `rateLimit_${action}`;
    const now = Date.now();
    
    let attempts: number[] = JSON.parse(localStorage.getItem(key) || '[]');
    
    // Supprimer les tentatives trop anciennes
    attempts = attempts.filter(timestamp => now - timestamp < windowMs);
    
    if (attempts.length >= maxAttempts) {
      const oldestAttempt = Math.min(...attempts);
      const timeRemaining = Math.ceil((windowMs - (now - oldestAttempt)) / 1000);
      
      return {
        allowed: false,
        timeRemaining,
        message: `Too many attempts. Please wait ${timeRemaining} seconds.`
      };
    }
    
    // Ajouter la tentative actuelle
    attempts.push(now);
    localStorage.setItem(key, JSON.stringify(attempts));
    
    return {
      allowed: true,
      attemptsRemaining: maxAttempts - attempts.length,
      message: 'Request allowed'
    };
  }

  /**
   * 🔒 Reset du rate limiting
   */
  resetRateLimit(action: string): void {
    const key = `rateLimit_${action}`;
    localStorage.removeItem(key);
  }
}

// Instance singleton
const secureValidator = new SecureInputValidator();

export default secureValidator;