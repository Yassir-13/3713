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