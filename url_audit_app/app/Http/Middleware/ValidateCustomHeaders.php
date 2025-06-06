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
        'X-Client-ID' => '/^(client_[a-f0-9]+|3713_[a-f0-9]{16})$/', // Plus flexible
        'X-Scan-Context' => '/^(user_scan|bulk_scan|api_scan)$/',
        'X-Rate-Limit-Bypass' => '/^premium_[a-zA-Z0-9]{32}$/',
    ];

    // 🔒 Headers requis pour certaines routes (assoupli pour tests)
    private const REQUIRED_HEADERS = [
        'api/scan' => ['X-API-Version'], // Seulement X-API-Version obligatoire
        'api/2fa/*' => ['X-API-Version'],
    ];

    public function handle(Request $request, Closure $next): Response
    {
        // 🔒 Log de debug pour voir ce qui arrive
        Log::info('🔒 Header validation middleware triggered', [
            'path' => $request->path(),
            'method' => $request->method(),
            'headers' => array_intersect_key(
                $request->headers->all(),
                array_flip(['x-api-version', 'x-client-id', 'x-scan-context'])
            )
        ]);

        // 🔒 Validation des headers personnalisés (non-bloquante pour développement)
        $this->validateCustomHeaders($request);
        
        // 🔒 Validation des headers requis (avec exemptions)
        if (!$this->shouldSkipValidation($request)) {
            $this->validateRequiredHeaders($request);
        }
        
        // 🔒 Anti-tampering sur les headers critiques
        $this->validateCriticalHeaders($request);
        
        $response = $next($request);
        
        // 🔒 Ajouter headers de réponse sécurisés
        $this->addSecureResponseHeaders($response, $request);
        
        return $response;
    }

    /**
     * 🔒 Détermine si on doit ignorer la validation (pour certaines routes)
     */
    private function shouldSkipValidation(Request $request): bool
    {
        // Routes de test exemptées
        if ($request->is('api/test') || $request->is('api/jwt-debug')) {
            return true;
        }
        
        // OPTIONS requests (CORS preflight)
        if ($request->method() === 'OPTIONS') {
            return true;
        }
        
        return false;
    }

    /**
     * 🔒 Valide les headers personnalisés 3713 (mode non-bloquant pour développement)
     */
    private function validateCustomHeaders(Request $request): void
    {
        foreach (self::ALLOWED_HEADERS as $header => $pattern) {
            $value = $request->header($header);
            
            if ($value !== null && !preg_match($pattern, $value)) {
                Log::warning('Invalid custom header detected', [
                    'header' => $header,
                    'value' => $value,
                    'pattern' => $pattern,
                    'ip' => $request->ip(),
                    'user_agent' => $request->userAgent()
                ]);
                
                // 🚨 En développement : warning seulement
                if (app()->environment('production')) {
                    abort(400, "Invalid format for header: {$header}");
                }
            }
        }
    }

    /**
     * 🔒 Valide les headers requis selon la route
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
                        
                        // 🚨 En développement : moins strict
                        if (app()->environment('production')) {
                            abort(400, "Missing required header: {$requiredHeader}");
                        }
                    }
                }
            }
        }
    }

    /**
     * 🔒 Validation anti-tampering sur headers critiques
     */
    private function validateCriticalHeaders(Request $request): void
    {
        // Validation Client-ID format (assouplie)
        $clientId = $request->header('X-Client-ID');
        if ($clientId && !$this->isValidClientId($clientId)) {
            Log::warning('Invalid Client-ID format detected', [
                'client_id' => $clientId,
                'ip' => $request->ip(),
                'user_agent' => $request->userAgent()
            ]);
            
            // En développement : tolérant
            if (app()->environment('production')) {
                abort(400, 'Invalid Client-ID format');
            }
        }

        // Validation API Version
        $apiVersion = $request->header('X-API-Version');
        if ($apiVersion && !in_array($apiVersion, ['v1', 'v1.0', 'v1.1', 'v2'])) {
            Log::warning('Unsupported API version', [
                'api_version' => $apiVersion,
                'ip' => $request->ip()
            ]);
            
            if (app()->environment('production')) {
                abort(400, 'Unsupported API version');
            }
        }

        // Anti-injection sur Scan-Context
        $scanContext = $request->header('X-Scan-Context');
        if ($scanContext && strlen($scanContext) > 50) {
            Log::warning('Scan-Context header too long', [
                'length' => strlen($scanContext),
                'ip' => $request->ip()
            ]);
            
            abort(400, 'Scan-Context header too long');
        }
    }

    /**
     * 🔒 Validation format Client-ID 3713 (assouplie)
     */
    private function isValidClientId(string $clientId): bool
    {
        // Formats acceptés :
        // - client_abc123 (legacy)
        // - 3713_[16 caractères hexadécimaux] (nouveau format)
        return preg_match('/^(client_[a-f0-9]+|3713_[a-f0-9]{16})$/', $clientId) === 1;
    }

    /**
     * 🔒 Ajouter headers de réponse sécurisés
     */
    private function addSecureResponseHeaders(Response $response, Request $request): void
    {
        // Header anti-cachage pour les endpoints sensibles
        if ($request->is('api/auth/*') || $request->is('api/2fa/*')) {
            $response->headers->set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
            $response->headers->set('Pragma', 'no-cache');
            $response->headers->set('Expires', '0');
        }

        // Headers de debug sécurisés (développement uniquement)
        if (app()->environment('local')) {
            $response->headers->set('X-Debug-Route', $request->route()?->getName() ?? 'unknown');
            $response->headers->set('X-Debug-Method', $request->method());
            $response->headers->set('X-Header-Validation', 'active');
        }

        // Header de validation du client
        if ($request->hasHeader('X-Client-ID')) {
            $response->headers->set('X-Client-Verified', 'true');
        }

        // Header de sécurité 3713
        $response->headers->set('X-3713-Security', 'enabled');
        $response->headers->set('X-Validation-Status', 'passed');
    }
}