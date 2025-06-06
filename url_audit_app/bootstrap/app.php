<?php
// bootstrap/app.php - VERSION SÉCURISÉE FINALE avec middlewares actifs

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Support\Facades\Log;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        // 🔒 MIDDLEWARES DE SÉCURITÉ CRITIQUES
        
        // 1. Désactiver CSRF pour API (JWT utilisé)
        $middleware->validateCsrfTokens(except: [
            'api/*'
        ]);
        
        // 2. ENREGISTREMENT des middlewares personnalisés
        $middleware->alias([
            'jwt.auth' => \App\Http\Middleware\JWTAuth::class,
            'validate.headers' => \App\Http\Middleware\ValidateCustomHeaders::class,
            'security.headers' => \App\Http\Middleware\SecurityHeaders::class,
        ]);
        
        // 3. MIDDLEWARE GLOBAL pour toutes les requêtes API
        $middleware->api(prepend: [
            \Laravel\Sanctum\Http\Middleware\EnsureFrontendRequestsAreStateful::class,
        ]);
        
        // 🔒 4. AJOUT GLOBAL des headers de sécurité
        $middleware->append(\App\Http\Middleware\SecurityHeaders::class);
        
        // 🔒 5. VALIDATION des headers personnalisés pour API
        $middleware->appendToGroup('api', [
            \App\Http\Middleware\ValidateCustomHeaders::class
        ]);
        
        // 6. Priorité des middlewares
        $middleware->priority([
            \App\Http\Middleware\SecurityHeaders::class,
            \App\Http\Middleware\ValidateCustomHeaders::class,
            \App\Http\Middleware\JWTAuth::class,
        ]);
        
        // 🔒 7. MIDDLEWARE pour routes spécifiques
        $middleware->group('secure-api', [
            \App\Http\Middleware\SecurityHeaders::class,
            \App\Http\Middleware\ValidateCustomHeaders::class,
            'throttle:api',
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions) {
        // 🔒 Gestion sécurisée des erreurs JWT
        $exceptions->render(function (\Firebase\JWT\ExpiredException $exception) {
            Log::warning('JWT Token expired', ['message' => $exception->getMessage()]);
            return response()->json([
                'message' => 'Token expired',
                'error' => 'Please refresh your token or login again'
            ], 401);
        });
        
        $exceptions->render(function (\Firebase\JWT\SignatureInvalidException $exception) {
            Log::error('JWT Invalid signature', ['message' => $exception->getMessage()]);
            return response()->json([
                'message' => 'Invalid token signature',
                'error' => 'Authentication failed'
            ], 401);
        });
        
        // 🔒 Gestion des erreurs de headers
        $exceptions->render(function (\Symfony\Component\HttpKernel\Exception\BadRequestHttpException $exception) {
            Log::warning('Bad request (possibly invalid headers)', [
                'message' => $exception->getMessage(),
                'ip' => request()->ip()
            ]);
            return response()->json([
                'message' => 'Bad request',
                'error' => 'Invalid request format or headers'
            ], 400);
        });
    })->create();