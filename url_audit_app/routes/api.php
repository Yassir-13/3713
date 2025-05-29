<?php

use Illuminate\Http\Request;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\TwoFactorController;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ScanController;

// Public routes (pas de middleware)
Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);

// Routes protégées avec le middleware 'auth:sanctum'
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/auth/logout', [AuthController::class, 'logout']);
    
    // 🆕 ROUTES 2FA - CRITIQUES
    Route::prefix('2fa')->group(function () {
        Route::get('/status', [TwoFactorController::class, 'getStatus']);
        Route::post('/generate', [TwoFactorController::class, 'generateSecret']);
        Route::post('/confirm', [TwoFactorController::class, 'confirmTwoFactor']);
        Route::post('/disable', [TwoFactorController::class, 'disableTwoFactor']);
        Route::post('/recovery-codes', [TwoFactorController::class, 'regenerateRecoveryCodes']);
        Route::post('/verify', [TwoFactorController::class, 'verifyCode']);
    });
    
    // Routes protégées pour les scans des utilisateurs authentifiés
    Route::get('/user-scans', [ScanController::class, 'getUserScans']);
    Route::post('/scan/{scanId}/favorite', [ScanController::class, 'toggleFavorite']);
    Route::get('/favorites', [ScanController::class, 'getFavorites']);
});

// Routes de scan
Route::post('/scan', [ScanController::class, 'scan']);
Route::get('/scan-results/{scan_id}', [ScanController::class, 'getResults']);
Route::get('/search-scans', [ScanController::class, 'searchScans']);
Route::get('/scan-history', [ScanController::class, 'getUserScans']);

// Nouvelle route pour la génération de rapports via Gemini
Route::post('/generate-report', [ScanController::class, 'generateReport']);