<?php
// app/Http/Middleware/SecurityHeaders.php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class SecurityHeaders
{
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        // 🔒 Headers de sécurité critiques
        $securityHeaders = [
            // Protection XSS
            'X-XSS-Protection' => '1; mode=block',
            
            // Prévention MIME sniffing
            'X-Content-Type-Options' => 'nosniff',
            
            // Protection contre le clickjacking
            'X-Frame-Options' => 'DENY',
            
            // Référrer policy
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
            
            // Permissions policy (remplace Feature-Policy)
            'Permissions-Policy' => 'camera=(), microphone=(), geolocation=(), payment=()',
            
            // Remove server info
            'Server' => '3713-Security-Scanner',
            
            // API Version header
            'X-API-Version' => 'v1.0',
            
            // Response time for monitoring
            'X-Response-Time' => round((microtime(true) - LARAVEL_START) * 1000, 2) . 'ms',
        ];

        // 🔒 Content Security Policy pour l'API
        if ($request->is('api/*')) {
            $securityHeaders['Content-Security-Policy'] = 
                "default-src 'none'; " .
                "script-src 'none'; " .
                "style-src 'none'; " .
                "img-src 'none'; " .
                "connect-src 'self'; " .
                "font-src 'none'; " .
                "object-src 'none'; " .
                "media-src 'none'; " .
                "frame-src 'none'; " .
                "sandbox; " .
                "base-uri 'none'";
        }

        // 🔒 HSTS pour HTTPS uniquement
        if ($request->secure()) {
            $securityHeaders['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
        }

        // 🔒 Headers spécifiques à 3713
        if ($request->is('api/scan*')) {
            $securityHeaders['X-Scan-Context'] = 'security-audit';
            $securityHeaders['X-Content-Trust'] = 'verified';
        }

        // Appliquer tous les headers
        foreach ($securityHeaders as $key => $value) {
            $response->headers->set($key, $value);
        }

        // 🔒 Supprimer les headers révélateurs
        $response->headers->remove('X-Powered-By');
        $response->headers->remove('x-turbo-charged-by');

        return $response;
    }
}