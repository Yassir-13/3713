<?php
// config/cors.php - Configuration CORS SÉCURISÉE et FONCTIONNELLE

return [
    /*
    |--------------------------------------------------------------------------
    | Cross-Origin Resource Sharing (CORS) Configuration
    |--------------------------------------------------------------------------
    | ⚠️ CRITIQUE : Cette config détermine qui peut accéder à votre API
    */

    // 🔒 Chemins où CORS s'applique
    'paths' => [
        'api/*',                    // ✅ Toutes les routes API
        'up',                       // ✅ Health check Laravel 11
    ],

    // 🔒 Méthodes HTTP autorisées
    'allowed_methods' => [
        'GET', 
        'POST', 
        'PUT', 
        'PATCH', 
        'DELETE', 
        'OPTIONS'  // ⚠️ CRITIQUE pour preflight
    ],

    // 🔒 Origins autorisés - STRICT et SÉCURISÉ
    'allowed_origins' => env('APP_ENV') === 'production' 
        ? [
            // 🚨 PRODUCTION : Seulement vos domaines
            env('FRONTEND_URL'),
            'https://yourdomain.com',
            'https://app.yourdomain.com',
        ] 
        : [
            // 🧪 DÉVELOPPEMENT : Origins locaux uniquement
            'http://localhost:5173',    // Vite React
            'http://localhost:3000',    // Create React App
            'http://127.0.0.1:5173',   // IP variant
            'http://127.0.0.1:3000',   // IP variant
            env('FRONTEND_URL', 'http://localhost:5173'),
        ],

    // 🔒 Patterns d'origins (plus flexible mais contrôlé)
    'allowed_origins_patterns' => env('APP_ENV') === 'production' 
        ? [] 
        : [
            // Seulement en développement
            '/^http:\/\/localhost:\d+$/',
            '/^http:\/\/127\.0\.0\.1:\d+$/',
        ],

    /*
    |--------------------------------------------------------------------------
    | Headers autorisés - Liste stricte et validée
    |--------------------------------------------------------------------------
    */
    'allowed_headers' => [
        // 🔐 Authentification & Sécurité
        'Authorization',            // JWT Bearer tokens
        'X-CSRF-TOKEN',            // Protection CSRF (optionnel avec JWT)
        
        // 📡 Communication standard HTTP
        'Content-Type',             // application/json
        'Accept',                   // Content negotiation
        'Accept-Language',          // Langue
        'Accept-Encoding',          // Compression
        'Origin',                   // CORS origin
        'X-Requested-With',         // XMLHttpRequest detection
        
        // 🎯 Headers spécifiques à 3713 (validés par middleware)
        'X-API-Version',           // API versioning
        'X-Client-ID',             // Client fingerprinting
        'X-Scan-Context',          // Type de scan
        'X-Rate-Limit-Bypass',     // Token premium
        
        // 🗂️ Cache & Performance
        'Cache-Control',           // Directives cache
        'Pragma',                  // Legacy cache
        'If-None-Match',           // ETag validation
        'If-Modified-Since',       // Modification check
        'User-Agent',              // Client info
    ],

    /*
    |--------------------------------------------------------------------------
    | Headers exposés - Visibles côté client React
    |--------------------------------------------------------------------------
    */
    'exposed_headers' => [
        // 🔐 JWT & Auth
        'Authorization',            // Nouveau token après refresh
        
        // 📊 Rate Limiting & Quotas (pour UI)
        'X-RateLimit-Remaining',   // Scans restants
        'X-RateLimit-Reset',       // Timestamp reset quotas
        'X-RateLimit-Limit',       // Limite totale
        
        // 🎯 Metadata 3713 pour UI en temps réel
        'X-Scan-Progress',         // Progression scan (0-100%)
        'X-Scan-Status',           // pending, running, completed
        'X-Security-Score',        // Score calculé (0-10)
        'X-Scan-ID',              // ID du scan en cours
        
        // 🛠️ Metadata système
        'X-API-Version',           // Version API
        'X-Response-Time',         // Temps de réponse
        'X-3713-Security',         // Statut sécurité
        'X-Client-Verified',       // Client validé
        'X-Validation-Status',     // Status validation headers
        
        // 📦 Cache pour performance
        'ETag',                    // Cache validation
        'Last-Modified',           // Date modification
        'Content-Length',          // Taille réponse
    ],

    /*
    |--------------------------------------------------------------------------
    | Configuration comportementale
    |--------------------------------------------------------------------------
    */
    
    // 🔒 Durée de cache des réponses CORS preflight
    'max_age' => env('APP_ENV') === 'production' 
        ? 3600    // 1 heure en production (performance)
        : 0,      // Pas de cache en développement (flexibilité)
    
    // 🔒 Support des credentials (cookies, authorization headers)
    'supports_credentials' => true,  // Nécessaire pour JWT dans Authorization header
];

/*
|--------------------------------------------------------------------------
| 📝 Notes de débogage CORS
|--------------------------------------------------------------------------
| 
| Pour tester votre config CORS :
| 
| 1. Preflight test (OPTIONS) :
|    curl -H "Origin: http://localhost:5173" \
|         -H "Access-Control-Request-Method: POST" \
|         -H "Access-Control-Request-Headers: Content-Type,Authorization" \
|         -X OPTIONS http://localhost:8000/api/test
| 
| 2. Test origin valide :
|    curl -H "Origin: http://localhost:5173" \
|         -X GET http://localhost:8000/api/test
| 
| 3. Test origin invalide (doit être rejeté) :
|    curl -H "Origin: http://malicious.com" \
|         -X GET http://localhost:8000/api/test
| 
| 4. Vérification headers exposés :
|    curl -v -H "Origin: http://localhost:5173" \
|         http://localhost:8000/api/test
| 
| Si le test 3 passe, votre CORS n'est pas correctement configuré !
|--------------------------------------------------------------------------
*/