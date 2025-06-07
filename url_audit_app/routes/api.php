<?php

use Illuminate\Http\Request;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\TwoFactorController;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ScanController;

// 🔧 ROUTES AUTH JWT - Publiques (pas de middleware)
Route::prefix('auth')->group(function () {
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/login', [AuthController::class, 'login']); // ✅ Gère 2FA directement
    Route::post('/refresh', [AuthController::class, 'refresh']);
});

// 🔧 ROUTES AUTH JWT - Protégées par JWT middleware
Route::prefix('auth')->middleware('jwt.auth')->group(function () {
    Route::get('/me', [AuthController::class, 'me']);
    Route::post('/logout', [AuthController::class, 'logout']);
});

// 🆕 ROUTES 2FA - Protégées par JWT (pour la gestion des paramètres 2FA)
Route::prefix('2fa')->middleware('jwt.auth')->group(function () {
    Route::get('/status', [TwoFactorController::class, 'getStatus']);
    Route::post('/generate', [TwoFactorController::class, 'generateSecret']);
    Route::post('/confirm', [TwoFactorController::class, 'confirmTwoFactor']);
    Route::post('/disable', [TwoFactorController::class, 'disableTwoFactor']);
    Route::post('/recovery-codes', [TwoFactorController::class, 'regenerateRecoveryCodes']);
    Route::post('/verify', [TwoFactorController::class, 'verifyCode']);
});

// 🔧 ROUTES SCAN - Protégées par JWT avec permission basic_scan
Route::middleware(['jwt.auth:basic_scan'])->group(function () {
    Route::post('/scan', [ScanController::class, 'scan']);
    Route::get('/scan-results/{scan_id}', [ScanController::class, 'getResults']);
    Route::get('/search-scans', [ScanController::class, 'searchScans']);
    Route::get('/scan-history', [ScanController::class, 'getUserScans']);
    Route::get('/user-scans', [ScanController::class, 'getUserScans']);
    Route::post('/generate-report', [ScanController::class, 'generateReport']);
    
    // Routes favorites
    Route::post('/scan/{scanId}/favorite', [ScanController::class, 'toggleFavorite']);
    Route::get('/favorites', [ScanController::class, 'getFavorites']);
});

// 🔧 ROUTES DE TEST
Route::get('/test', function () {
    return response()->json([
        'message' => '3713 API is working!',
        'timestamp' => now()->toISOString(),
        'version' => '1.0.0-jwt-simplified',
        'environment' => app()->environment()
    ]);
});

// 🔧 ROUTE DE DEBUG JWT (protégée)
Route::middleware('jwt.auth')->get('/jwt-debug', function (Request $request) {
    $payload = $request->attributes->get('jwt_payload');
    
    return response()->json([
        'message' => 'JWT Debug Info',
        'payload_exists' => !!$payload,
        'user_id' => $payload->sub ?? 'missing',
        'permissions' => $payload->security->scan_permissions ?? [],
        'expires_at' => isset($payload->exp) ? date('Y-m-d H:i:s', $payload->exp) : 'missing',
        'two_factor_verified' => $payload->security->two_factor_verified ?? false
    ]);
});

Route::get('/security-test', function (Request $request) {
    // Récupérer tous les headers de la requête
    $allHeaders = $request->headers->all();
    
    // Headers spécifiques à 3713
    $customHeaders = [
        'X-API-Version' => $request->header('X-API-Version'),
        'X-Client-ID' => $request->header('X-Client-ID'),
        'X-Scan-Context' => $request->header('X-Scan-Context'),
        'Origin' => $request->header('Origin'),
        'User-Agent' => $request->header('User-Agent'),
    ];
    
    // Test de validation
    $validationTests = [
        'cors_origin_allowed' => in_array($request->header('Origin'), [
            'http://localhost:5173',
            'http://localhost:3000',
            'http://127.0.0.1:5173',
            'http://127.0.0.1:3000'
        ]),
        'api_version_present' => !empty($request->header('X-API-Version')),
        'client_id_format' => $request->header('X-Client-ID') ? 
            preg_match('/^(client_[a-f0-9]+|3713_[a-f0-9]{16})$/', $request->header('X-Client-ID')) : 
            null,
        'security_middleware_active' => $request->hasHeader('X-3713-Security'),
    ];
    
    return response()->json([
        'message' => '🔒 3713 Security Test Response',
        'timestamp' => now()->toISOString(),
        'request_info' => [
            'method' => $request->method(),
            'path' => $request->path(),
            'ip' => $request->ip(),
            'origin' => $request->header('Origin'),
        ],
        'custom_headers' => $customHeaders,
        'validation_tests' => $validationTests,
        'security_status' => [
            'cors_enabled' => true,
            'headers_validated' => true,
            'environment' => app()->environment(),
            'middleware_active' => [
                'security_headers' => $request->hasHeader('X-3713-Security'),
                'validation_headers' => $request->hasHeader('X-Validation-Status'),
            ]
        ],
        'recommendations' => $this->getSecurityRecommendations($validationTests)
    ]);
})->name('security.test');
