<?php

namespace App\Http\Controllers;

use App\Models\ScanResult;
use App\Models\ScanHistory;
use App\Services\JWTService;
use Illuminate\Support\Str;
use App\Jobs\ScanWebsite;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\RateLimiter;

class ScanController extends Controller
{
    protected JWTService $jwtService;

    public function __construct(JWTService $jwtService)
    {
        $this->jwtService = $jwtService;
    }

    /**
     * Méthode utilitaire pour obtenir l'utilisateur authentifié via JWT
     */
    private function getAuthenticatedUser(Request $request)
    {
        // Le middleware JWT aura injecté le payload
        $payload = $request->attributes->get('jwt_payload');
        
        if (!$payload) {
            Log::warning('JWT Payload missing in ScanController', [
                'path' => $request->path(),
                'method' => $request->method()
            ]);
            return null;
        }
        
        // Retourner un objet user avec les données du token
        return (object) [
            'id' => $payload->sub,
            'email' => $payload->user->email,
            'name' => $payload->user->name,
            'two_factor_enabled' => $payload->user->two_factor_enabled,
            'permissions' => $payload->security->scan_permissions ?? [],
            'quotas' => $payload->quotas ?? (object)['daily_scans' => 10]
        ];
    }

    /**
     * SÉCURISATION MAJEURE: Validation stricte des URLs
     */
    private function validateScanUrl($url)
    {
        // Validation format de base
        $validator = Validator::make(['url' => $url], [
            'url' => [
                'required',
                'string',
                'max:2048',
                'regex:/^https?:\/\/[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?(?:\/[^\s]*)?$/',
            ]
        ]);

        if ($validator->fails()) {
            return [
                'valid' => false, 
                'error' => 'URL format invalid or too long'
            ];
        }

        //  Parsing 
        $components = parse_url($url);
        if (!$components || !isset($components['host'])) {
            return [
                'valid' => false,
                'error' => 'Malformed URL structure'
            ];
        }

        $host = $components['host'];

        // Validation hostname 
        if (!preg_match('/^[a-zA-Z0-9.-]+$/', $host)) {
            return [
                'valid' => false,
                'error' => 'Hostname contains unauthorized characters'
            ];
        }

        // Blacklist IPs privées/dangereuses
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            if (!filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return [
                    'valid' => false,
                    'error' => 'Private/reserved IP addresses not allowed'
                ];
            }
        }

        // Blacklist de domaines dangereux
        $dangerousDomains = [
            'localhost',
            'metadata.google.internal',
            '169.254.169.254', // AWS metadata
            'internal',
            'admin',
            'test'
        ];

        foreach ($dangerousDomains as $dangerous) {
            if (stripos($host, $dangerous) !== false) {
                return [
                    'valid' => false,
                    'error' => 'Domain not allowed for security reasons'
                ];
            }
        }

        return ['valid' => true, 'url' => $url, 'host' => $host];
    }

    /**
     * LANCEMENT DE SCAN - Adapté pour JWT
     */
   public function scan(Request $request)
    {
        // SÉCURITÉ 1: Validation stricte des entrées
        $request->validate([
            'url' => 'required|string|max:2048',
        ]);
        
        $inputUrl = trim($request->input('url'));
        
        // SÉCURITÉ 2: Validation avancée de l'URL
        $urlValidation = $this->validateScanUrl($inputUrl);
        if (!$urlValidation['valid']) {
            return response()->json([
                'message' => 'Invalid URL provided',
                'error' => $urlValidation['error'],
                'provided_url_length' => strlen($inputUrl)
            ], 422);
        }
        
        $url = $urlValidation['url'];
        
        // SÉCURITÉ 3: Récupérer user depuis JWT
        $user = $this->getAuthenticatedUser($request);
        if (!$user) {
            return response()->json([
                'message' => 'Authentication required',
                'error' => 'Token JWT invalide ou payload manquant'
            ], 401);
        }
        
        // 🔧 CORRECTION : Vérifier permissions de scan depuis le token
        if (!in_array('basic_scan', $user->permissions)) {
            Log::warning('Scan permission denied', [
                'user_id' => $user->id,
                'required' => 'basic_scan',
                'has_permissions' => $user->permissions
            ]);
            
            return response()->json([
                'message' => 'Permission denied',
                'error' => 'Autorisation de scan requise'
            ], 403);
        }
        
        // Vérifier quotas depuis le token
        $dailyScans = $user->quotas->daily_scans ?? 10;
        if ($dailyScans <= 0) {
            return response()->json([
                'message' => 'Quota exceeded',
                'error' => 'Limite de scans journaliers atteinte'
            ], 429);
        }
        
        $rateLimitKey = 'scan-limit:' . $user->id;
        if (RateLimiter::tooManyAttempts($rateLimitKey, 10)) {
            $seconds = RateLimiter::availableIn($rateLimitKey);
            return response()->json([
                'message' => 'Rate limit exceeded',
                'error' => 'Too many scan attempts. Please wait.',
                'retry_after_seconds' => $seconds
            ], 429);
        }
        
        RateLimiter::hit($rateLimitKey, 3600);
        
        // Vérifier les scans récents
        $recentScan = ScanResult::where('url', $url)
                                ->where('user_id', $user->id)
                                ->where('created_at', '>', now()->subMinutes(5))
                                ->first();
        
        if ($recentScan) {
            return response()->json([
                'message' => 'Recent scan exists',
                'scan_id' => $recentScan->scan_id,
                'url' => $recentScan->url,
                'status' => $recentScan->status,
                'created_at' => $recentScan->created_at,
                'is_recent_duplicate' => true
            ], 200);
        }
        
        try {
            // Création du scan
            $scan = ScanResult::create([
                'scan_id' => Str::uuid(),
                'url' => $url,
                'status' => 'pending',
                'user_id' => $user->id
            ]);
            
            ScanHistory::create([
                'scan_id' => $scan->scan_id,
                'user_id' => $user->id,
                'url' => $url,
                'status' => 'pending'
            ]);
            
            // Lancer le job
            ScanWebsite::dispatch($url, $scan->scan_id)->delay(now()->addSeconds(2));
            
            Log::info("JWT Secure scan started", [
                'scan_id' => $scan->scan_id,
                'user_id' => $user->id,
                'url_host' => $urlValidation['host'],
                'permissions' => $user->permissions,
                'ip' => $request->ip()
            ]);
            
            return response()->json([
                'message' => 'Scan started successfully',
                'scan_id' => $scan->scan_id,
                'url' => $url,
                'status' => 'pending',
                'estimated_duration' => '5-15 minutes',
                'user_permissions' => $user->permissions
            ], 202);
            
        } catch (\Exception $e) {
            Log::error("JWT Secure scan creation failed", [
                'error' => $e->getMessage(),
                'user_id' => $user->id,
                'url_host' => $urlValidation['host'] ?? 'unknown',
                'ip' => $request->ip()
            ]);
            
            return response()->json([
                'message' => 'Failed to start scan',
                'error' => 'Internal server error occurred'
            ], 500);
        }
    }
    /**
     * RÉCUPÉRATION DES RÉSULTATS - Adapté pour JWT
     */
    public function getResults(Request $request, $scan_id)
    {
        if (!Str::isUuid($scan_id)) {
            return response()->json([
                'message' => 'Invalid scan ID format',
                'error' => 'Scan ID must be a valid UUID'
            ], 422);
        }
        
        try {
            $scan = ScanResult::where('scan_id', $scan_id)->first();
            
            if (!$scan) {
                return response()->json([
                    'message' => 'Scan not found',
                    'error' => 'The requested scan does not exist'
                ], 404);
            }
            
            // 🔧 CORRECTION : Contrôle d'accès JWT
            $user = $this->getAuthenticatedUser($request);
            if (!$user) {
                return response()->json([
                    'message' => 'Authentication required',
                    'error' => 'Token JWT invalide ou payload manquant'
                ], 401);
            }
            
            // Vérification de propriété du scan
            if ($scan->user_id && $scan->user_id !== $user->id) {
                return response()->json([
                    'message' => 'Access denied',
                    'error' => 'You do not have permission to view this scan'
                ], 403);
            }
            
            // Messages personnalisés
            $clientMessage = match($scan->status) {
                'timeout' => "Your scan is taking longer than expected. Please be patient, we're still working on it.",
                'failed' => "We encountered an issue while scanning this website. Please check back in a few minutes.",
                'running' => "Your scan is in progress. This may take several minutes for complex websites.",
                'completed' => "Ta-da ! Your scan is completed! You can now check the results.",
                default => "Scan status: " . $scan->status
            };
            
            Log::info("JWT Secure scan results accessed", [
                'scan_id' => $scan->scan_id,
                'user_id' => $user->id,
                'scan_status' => $scan->status,
                'ip' => $request->ip()
            ]);
            
            return response()->json([
                'id' => $scan->scan_id,
                'scan_id' => $scan->scan_id,
                'url' => $scan->url,
                'status' => $scan->status ?? 'unknown',
                'created_at' => $scan->created_at,
                'whatweb_output' => $scan->whatweb_output,
                'sslyze_output' => $scan->sslyze_output,
                'zap_output' => $scan->zap_output,
                'nuclei_output' => $scan->nuclei_output, 
                'error' => $scan->error,
                'gemini_analysis' => $scan->gemini_analysis,
                'user_message' => $clientMessage,
                'is_owner' => true
            ]);
            
        } catch (\Exception $e) {
            Log::error("JWT Secure get results error", [
                'error' => $e->getMessage(),
                'scan_id' => $scan_id,
                'ip' => $request->ip()
            ]);
            
            return response()->json([
                'message' => 'Error retrieving scan results',
                'error' => 'Internal server error occurred'
            ], 500);
        }
    }

    /**
     * RECHERCHE DE SCANS - Adapté pour JWT
     */
    public function searchScans(Request $request)
    {   
        //Authentification requise
        $user = $this->getAuthenticatedUser($request);
        if (!$user) {
            return response()->json(['message' => 'Authentication required'], 401);
        }
        
        //Validation des paramètres de recherche
        $query = $request->input('q') ?? $request->input('url');
        
        if ($query && strlen($query) > 255) {
            return response()->json([
                'message' => 'Search query too long',
                'error' => 'Search query must be less than 255 characters'
            ], 422);
        }
        
        try {
            //Recherche limitée aux scans de l'utilisateur
            $scansQuery = ScanHistory::forUser($user->id);
            
            if (!empty($query)) {
                // Recherche sécurisée par URL avec LIKE échappé
                $scansQuery->where(function($q) use ($query) {
                    $q->where('url', 'like', '%' . str_replace(['%', '_'], ['\%', '\_'], $query) . '%');
                });
            }
            
            $scans = $scansQuery->orderBy('created_at', 'desc')
                          ->limit(50)
                          ->get(['scan_id', 'url', 'status', 'created_at', 'is_favorite']);
            
            // Transformer les résultats
            $formattedScans = $scans->map(function($scan) {
                return [
                    'id' => $scan->scan_id,
                    'scan_id' => $scan->scan_id,
                    'url' => $scan->url,
                    'status' => $scan->status,
                    'created_at' => $scan->created_at,
                    'is_favorite' => $scan->is_favorite
                ];
            });
            
            return response()->json($formattedScans);
            
        } catch (\Exception $e) {
            Log::error("JWT Secure search scans error", [
                'error' => $e->getMessage(),
                'user_id' => $user->id,
                'query_length' => strlen($query ?? ''),
                'ip' => $request->ip()
            ]);
            
            return response()->json([
                'message' => 'Error searching scans',
                'error' => 'Internal server error occurred'
            ], 500);
        }
    }

    /**
     * SCANS UTILISATEUR - Adapté pour JWT
     */
    public function getUserScans(Request $request)
    {
        // SÉCURITÉ 1: Authentification obligatoire
        $user = $this->getAuthenticatedUser($request);
        
        if (!$user) {
            return response()->json([
                'message' => 'Authentication required',
                'error' => 'Token JWT invalide'
            ], 401);
        }
        
        try {
            // SÉCURITÉ 2: Validation du paramètre limit
            $limit = $request->input('limit', 20);
            $limit = max(1, min(100, (int)$limit)); // Entre 1 et 100
            
            // SÉCURITÉ 3: Récupération des scans de l'utilisateur uniquement
            $scans = ScanHistory::forUser($user->id)
                    ->completed()
                    ->orderBy('created_at', 'desc')
                    ->limit($limit)
                    ->get([
                        'scan_id', 
                        'url', 
                        'status', 
                        'created_at',
                        'is_favorite',
                        'last_viewed_at'
                    ]);
            
           $formattedScans = $scans->map(function($scan) {
                return [
                    'id' => $scan->scan_id,
                    'scan_id' => $scan->scan_id,
                    'url' => $scan->url,
                    'status' => $scan->status,
                    'created_at' => $scan->created_at,
                    'is_favorite' => $scan->is_favorite,
                    'last_viewed_at' => $scan->last_viewed_at
                ];
            });

            return response()->json($formattedScans);
            
        } catch (\Exception $e) {
            Log::error("JWT Secure get user scans error", [
                'error' => $e->getMessage(),
                'user_id' => $user->id,
                'ip' => $request->ip()
            ]);
            
            return response()->json([
                'message' => 'Error retrieving user scans',
                'error' => 'Internal server error occurred'
            ], 500);
        }
    }

    public function toggleFavorite(Request $request, $scanId)
    {
        $user = $this->getAuthenticatedUser($request);
        if (!$user) {
            return response()->json(['message' => 'Authentication required'], 401);
        }

        try {
            $history = ScanHistory::where('scan_id', $scanId)
                                 ->where('user_id', $user->id)
                                 ->first();

            if (!$history) {
                return response()->json(['message' => 'Scan not found'], 404);
            }

            $isFavorite = $history->toggleFavorite();

            return response()->json([
                'success' => true,
                'is_favorite' => $isFavorite,
                'message' => $isFavorite ? 'Added to favorites' : 'Removed from favorites'
            ]);

        } catch (\Exception $e) {
            return response()->json(['message' => 'Error updating favorite'], 500);
        }
    }

    public function getFavorites(Request $request)
    {
        $user = $this->getAuthenticatedUser($request);
        if (!$user) {
            return response()->json(['message' => 'Authentication required'], 401);
        }

        try {
            $favorites = ScanHistory::forUser($user->id)
                                   ->favorites()
                                   ->orderBy('created_at', 'desc')
                                   ->get(['scan_id', 'url', 'status', 'created_at']);

            return response()->json($favorites);

        } catch (\Exception $e) {
            return response()->json(['message' => 'Error retrieving favorites'], 500);
        }
    }

    /**
     * GÉNÉRATION DE RAPPORT - Adapté pour JWT
     */
    public function generateReport(Request $request)
    {
        // SÉCURITÉ 1: Authentification requise
        $user = $this->getAuthenticatedUser($request);
        if (!$user) {
            return response()->json([
                'message' => 'Authentication required',
                'error' => 'Token JWT invalide'
            ], 401);
        }
        
        // SÉCURITÉ 2: Validation du scan_id
        $scan_id = $request->input('scan_id');
        
        if (!$scan_id || !Str::isUuid($scan_id)) {
            return response()->json([
                'message' => 'Invalid scan ID',
                'error' => 'Scan ID is required and must be a valid UUID'
            ], 422);
        }
        
        try {
            // SÉCURITÉ 3: Vérification existence et propriété
            $scan = ScanResult::where('scan_id', $scan_id)->first();
            
            if (!$scan) {
                return response()->json([
                    'message' => 'Scan not found',
                    'error' => 'The requested scan does not exist'
                ], 404);
            }
            
            // SÉCURITÉ 4: Contrôle d'accès
            if ($scan->user_id !== $user->id) {
                return response()->json([
                    'message' => 'Access denied',
                    'error' => 'You do not have permission to generate reports for this scan'
                ], 403);
            }
            
            // SÉCURITÉ 5: Vérification statut du scan
            if ($scan->status !== 'completed') {
                return response()->json([
                    'message' => 'Cannot generate report',
                    'error' => 'Scan must be completed before generating a report',
                    'current_status' => $scan->status
                ], 400);
            }
            
            // SÉCURITÉ 6: Rate limiting pour génération de rapports
            $reportRateLimitKey = 'report-limit:' . $user->id;
            if (RateLimiter::tooManyAttempts($reportRateLimitKey, 5)) {
                $seconds = RateLimiter::availableIn($reportRateLimitKey);
                return response()->json([
                    'message' => 'Report generation rate limit exceeded',
                    'error' => 'Too many report generation attempts. Please wait.',
                    'retry_after_seconds' => $seconds
                ], 429);
            }
            
            RateLimiter::hit($reportRateLimitKey, 3600); // 1 heure
            
            // Relancer l'analyse Gemini
            ScanWebsite::dispatch($scan->url, $scan->scan_id)->delay(now());
            
            Log::info("JWT Secure report generation requested", [
                'scan_id' => $scan_id,
                'user_id' => $user->id,
                'url_host' => parse_url($scan->url, PHP_URL_HOST),
                'ip' => $request->ip()
            ]);
            
            return response()->json([
                'success' => true,
                'message' => 'Report regeneration started',
                'scan_id' => $scan_id,
                'estimated_completion' => '2-5 minutes'
            ]);
            
        } catch (\Exception $e) {
            Log::error("JWT Secure generate report error", [
                'error' => $e->getMessage(),
                'scan_id' => $scan_id,
                'user_id' => $user->id,
                'ip' => $request->ip()
            ]);
            
            return response()->json([
                'message' => 'Error generating report',
                'error' => 'Internal server error occurred'
            ], 500);
        }
    }
}