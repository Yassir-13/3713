<?php

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
        // 🔧 CRITIQUE : Désactiver CSRF pour toutes les routes API
        $middleware->validateCsrfTokens(except: [
            'api/*'
        ]);
        
        // JWT middleware alias
        $middleware->alias([
            'jwt.auth' => \App\Http\Middleware\JWTAuth::class,
        ]);
        
        // API middleware 
        $middleware->api(prepend: [
            \Laravel\Sanctum\Http\Middleware\EnsureFrontendRequestsAreStateful::class,
        ]);
        
        // Middleware priority
        $middleware->priority([
            \App\Http\Middleware\JWTAuth::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions) {
        // 🔧 Corriger les handlers JWT (optionnel - corrige juste le warning)
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
    })->create();