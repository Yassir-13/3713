<?php

use Illuminate\Http\Request;
use App\Http\Controllers\Api\AuthController;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ScanController;

// Public routes (pas de middleware)
Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);

// Routes protégées avec le middleware 'auth:sanctum'
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/auth/logout', [AuthController::class, 'logout']);
    
    // Routes protégées pour les scans des utilisateurs authentifiés
    Route::get('/user-scans', [ScanController::class, 'getUserScans']);
});

// Routes de scan
Route::post('/scan', [ScanController::class, 'scan']);
Route::get('/scan-results/{scan_id}', [ScanController::class, 'getResults']);
Route::get('/search-scans', [ScanController::class, 'searchScans']);
Route::get('/scan-history', [ScanController::class, 'getUserScans']); // Assurer la correspondance avec le front

// Nouvelle route pour la génération de rapports via Gemini
Route::post('/generate-report', [ScanController::class, 'generateReport']);