<?php

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as Middleware;

class VerifyCsrfToken extends Middleware
{
    /**
     * The URIs that should be excluded from CSRF verification.
     *
     * @var array<int, string>
     */
    protected $except = [
        // 🔧 Exclure TOUTES les routes API de la vérification CSRF
        'api/*',
        
        // Routes JWT spécifiques
        'api/auth/*',
        'api/2fa/*', 
        'api/scan',
        'api/scan-results/*',
        'api/search-scans',
        'api/scan-history',
        'api/user-scans',
        'api/generate-report',
        'api/scan/*/favorite',
        'api/favorites',
        'api/refresh',
        'api/test',
        'api/jwt-debug',
    ];
}