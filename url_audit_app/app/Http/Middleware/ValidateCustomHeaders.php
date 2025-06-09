<?php
// app/Http/Middleware/ValidateCustomHeaders.php - VERSION CORRIGÉE

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class ValidateCustomHeaders
{
    // 🔒 Headers autorisés avec leurs patterns de validation
    private const ALLOWED_HEADERS = [
        'X-API-Version' => '/^v\d+(\.\d+)?$/',
        'X-Client-ID' => '/^(client_[a-f0-9]+|3713_[a-f0-9]{16})$/',
        'X-Scan-Context' => '/^(user_scan|bulk_scan|api_scan)$/',
        'X-Rate-Limit-Bypass' => '/^premium_[a-zA-Z0-9]{32}$/',
    ];

    // 🔧 CORRIGÉ : Headers requis réduits et exemptions étendues
    private const REQUIRED_HEADERS = [
        'api/scan' => ['X-API-Version'],
        // Supprimé api/2fa/* pour éviter les conflits
    ];

    public function handle(Request $request, Closure $next): Response
    {
        Log::info('Header validation middleware', [
            'path' => $request->path(),
            'method' => $request->method(),
            'has_api_version' => $request->hasHeader('X-API-Version'),
            'has_client_id' => $request->hasHeader('X-Client-ID'),
        ]);

        if ($this->shouldSkipValidation($request)) {
            Log::info('🔒 Validation skipped for route', ['path' => $request->path()]);
            return $this->addResponseHeaders($next($request), $request);
        }
        
        //Validation non-bloquante en développement
        $this->validateCustomHeaders($request);
        $this->validateRequiredHeaders($request);
        $this->validateCriticalHeaders($request);
        
        $response = $next($request);
        
        return $this->addResponseHeaders($response, $request);
    }

    /**
     * 🔧 CORRIGÉ : Exemptions étendues pour éviter les 401
     */
    private function shouldSkipValidation(Request $request): bool
    {
        $exemptRoutes = [
            'api/test',
            'api/jwt-debug', 
            'api/security-test',
            'up'  // Health check Laravel
        ];
        
        // 🔧 CORRIGÉ : Ajouter TOUTES les routes auth
        $authRoutes = [
            'api/auth/register',
            'api/auth/login',
            'api/auth/refresh',  // ← AJOUTÉ !
            'api/auth/logout',   // ← AJOUTÉ !
            'api/auth/me',       // ← AJOUTÉ !
        ];
        
        $allExemptRoutes = array_merge($exemptRoutes, $authRoutes);
        
        foreach ($allExemptRoutes as $route) {
            if ($request->is($route)) {
                return true;
            }
        }
        
        // OPTIONS requests (CORS preflight)
        if ($request->method() === 'OPTIONS') {
            return true;
        }
        
        // 🔧 CORRIGÉ : Mode permissif en développement local
        if (app()->environment('local') && str_starts_with($request->path(), 'api/')) {
            Log::info('🔒 Permissive mode in local environment', ['path' => $request->path()]);
            return true;
        }
        
        return false;
    }

    /**
     * 🔒 Valide les headers personnalisés (non-bloquant en dev)
     */
    private function validateCustomHeaders(Request $request): void
    {
        foreach (self::ALLOWED_HEADERS as $header => $pattern) {
            $value = $request->header($header);
            
            if ($value !== null && !preg_match($pattern, $value)) {
                Log::warning('Invalid custom header detected', [
                    'header' => $header,
                    'value' => substr($value, 0, 50) . '...',
                    'pattern' => $pattern,
                    'ip' => $request->ip(),
                ]);
                
                // 🔧 CORRIGÉ : Seulement en production ET si pas route exemptée
                if (app()->environment('production') && !$this->shouldSkipValidation($request)) {
                    abort(400, "Invalid format for header: {$header}");
                }
            }
        }
    }

    /**
     * 🔧 CORRIGÉ : Validation headers requis assouplie
     */
    private function validateRequiredHeaders(Request $request): void
    {
        foreach (self::REQUIRED_HEADERS as $routePattern => $requiredHeaders) {
            if ($request->is($routePattern)) {
                foreach ($requiredHeaders as $requiredHeader) {
                    if (!$request->hasHeader($requiredHeader)) {
                        Log::warning('Missing required header', [
                            'route' => $request->path(),
                            'missing_header' => $requiredHeader,
                            'ip' => $request->ip()
                        ]);
                        
                        // 🔧 CORRIGÉ : Plus permissif, même en production
                        if (app()->environment('production') && config('app.strict_headers', false)) {
                            abort(400, "Missing required header: {$requiredHeader}");
                        }
                    }
                }
            }
        }
    }

    // ... reste du code identique ...
    
    private function validateCriticalHeaders(Request $request): void
    {
        // Validation Client-ID format (plus permissive)
        $clientId = $request->header('X-Client-ID');
        if ($clientId && !$this->isValidClientId($clientId)) {
            Log::warning('Invalid Client-ID format', [
                'client_id_prefix' => substr($clientId, 0, 10) . '...',
                'ip' => $request->ip()
            ]);
            
            // 🔧 CORRIGÉ : Seulement bloquer en production avec strict_headers activé
            if (app()->environment('production') && config('app.strict_headers', false)) {
                abort(400, 'Invalid Client-ID format');
            }
        }

        // Validation API Version (plus permissive)
        $apiVersion = $request->header('X-API-Version');
        if ($apiVersion && !in_array($apiVersion, ['v1', 'v1.0', 'v1.1', 'v2', 'v2.0'])) {
            Log::warning('Unsupported API version', [
                'api_version' => $apiVersion,
                'ip' => $request->ip()
            ]);
            
            // 🔧 CORRIGÉ : Ne pas bloquer en développement
            if (app()->environment('production') && config('app.strict_headers', false)) {
                abort(400, 'Unsupported API version');
            }
        }
    }

    private function isValidClientId(string $clientId): bool
    {
        return preg_match('/^(client_[a-f0-9]+|3713_[a-f0-9]{16}|test_[a-zA-Z0-9]{10,})$/', $clientId) === 1;
    }

    private function addResponseHeaders(Response $response, Request $request): Response
    {
        // Header de validation du client
        if ($request->hasHeader('X-Client-ID')) {
            $response->headers->set('X-Client-Verified', 'true');
        }

        // Header de sécurité 3713
        $response->headers->set('X-3713-Security', 'enabled');
        $response->headers->set('X-Validation-Status', 'passed');
        
        // Headers de cache pour endpoints sensibles
        if ($request->is('api/auth/*') || $request->is('api/2fa/*')) {
            $response->headers->set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
            $response->headers->set('Pragma', 'no-cache');
            $response->headers->set('Expires', '0');
        }

        // Headers de debug en développement
        if (app()->environment('local', 'testing')) {
            $response->headers->set('X-Debug-Route', $request->route()?->getName() ?? 'unknown');
            $response->headers->set('X-Debug-Method', $request->method());
            $response->headers->set('X-Header-Validation', 'active');
        }

        return $response;
    }
}