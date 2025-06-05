<?php
// config/cors.php - Configuration finale sécurisée pour 3713

return [
    /*
    |--------------------------------------------------------------------------
    | Cross-Origin Resource Sharing (CORS) Configuration
    |--------------------------------------------------------------------------
    | Configuration optimisée pour l'architecture 3713 (Laravel + React + JWT)
    */

    'paths' => [
        'api/*',                    // ✅ Toutes les routes API
        'up',                       // ✅ Health check Laravel 11
    ],

    'allowed_methods' => [
        'GET', 
        'POST', 
        'PUT', 
        'PATCH', 
        'DELETE', 
        'OPTIONS'
    ],

    'allowed_origins' => [
        'http://localhost:5173',    // ✅ React Vite dev
        'http://localhost:3000',    // ✅ React CRA dev
        'http://127.0.0.1:5173',   // ✅ IP variant
        'http://127.0.0.1:3000',   // ✅ IP variant
        // 🚀 Ajoutez votre domaine de production ici :
        // env('FRONTEND_URL'),
    ],

    'allowed_origins_patterns' => [],

    /*
    |--------------------------------------------------------------------------
    | Headers autorisés - Sécurisés et spécifiques à 3713
    |--------------------------------------------------------------------------
    */
    'allowed_headers' => [
        // 🔐 Authentification & Sécurité
        'Authorization',            // JWT Bearer tokens
        'X-CSRF-TOKEN',            // Protection CSRF
        'X-Client-ID',             // Client fingerprinting
        
        // 📡 Communication standard
        'Content-Type',             // application/json
        'Accept',                   // Content negotiation
        'Origin',                   // CORS origin
        'X-Requested-With',         // XMLHttpRequest
        
        // 🎯 Spécifique à 3713
        'X-API-Version',           // API versioning
        'X-Scan-Context',          // Type de scan (user, bulk, api)
        'X-Rate-Limit-Bypass',     // Token premium
        
        // 🗂️ Cache & Performance
        'Cache-Control',           // Directives cache
        'Pragma',                  // Legacy cache
        'If-None-Match',           // ETag validation
    ],

    /*
    |--------------------------------------------------------------------------
    | Headers exposés - Accessibles côté React
    |--------------------------------------------------------------------------
    */
    'exposed_headers' => [
        // 🔐 JWT & Auth
        'Authorization',            // Nouveau token après refresh
        
        // 📊 Rate Limiting & Quotas
        'X-RateLimit-Remaining',   // Scans restants
        'X-RateLimit-Reset',       // Timestamp reset quotas
        'X-RateLimit-Limit',       // Limite totale
        
        // 🎯 Spécifique 3713
        'X-Scan-Progress',         // Progression scan (0-100%)
        'X-Scan-Status',           // pending, running, completed
        'X-Security-Score',        // Score calculé (0-10)
        'X-Scan-ID',              // ID du scan en cours
        
        // 🛠️ Metadata
        'X-API-Version',           // Version API
        'X-Response-Time',         // Temps de réponse
    ],

    /*
    |--------------------------------------------------------------------------
    | Configuration
    |--------------------------------------------------------------------------
    */
    'max_age' => 0,                // Pas de cache CORS (sécurité dev)
    'supports_credentials' => true, // Nécessaire pour JWT + cookies
];