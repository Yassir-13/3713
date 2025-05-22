<?php

namespace App\Http\Controllers;

use App\Models\ScanResult;
use Illuminate\Support\Str;
use App\Jobs\ScanWebsite;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;

class ScanController extends Controller
{
    /**
     * Méthode utilitaire pour obtenir l'utilisateur authentifié via Sanctum
     */
    private function getAuthenticatedUser()
    {
        // Essayer d'abord avec le guard sanctum (pour les tokens Bearer)
        $user = Auth::guard('sanctum')->user();
        if ($user) {
            return $user;
        }
        
        // Fallback sur le guard web (pour les sessions)
        return Auth::guard('web')->user();
    }

    public function scan(Request $request)
    {
        // Validation de l'URL
        $request->validate([
            'url' => 'required|url'
        ]);
        
        $url = $request->input('url');
        
        // Vérifier si l'URL contient un protocole, ajouter https:// si nécessaire
        if (!preg_match("~^(?:f|ht)tps?://~i", $url)) {
            $url = "https://" . $url;
        }
        
        // Conserver l'URL complète pour l'affichage et la base de données
        $fullUrl = $url;
        
        // Extraire le domaine sans le protocole pour les outils de scan
        $cleanUrl = preg_replace("~^(?:f|ht)tps?://~i", "", $url);

        // Vérifier si un scan récent existe déjà pour cette URL
        $existingScan = ScanResult::where('url', $fullUrl)
                                  ->where('status', 'completed')
                                  ->latest()
                                  ->first();

        // Si un scan récent existe (moins de 24h), retourner ces résultats
        if ($existingScan && $existingScan->created_at->diffInHours(now()) < 24) {
            return response()->json([
                'message' => 'Recent scan found',
                'scan_id' => $existingScan->scan_id,
                'url' => $existingScan->url,
                'status' => $existingScan->status,
                'created_at' => $existingScan->created_at,
                'is_cached' => true
            ], 200);
        }
        
        try {
            // CORRECTION: Utiliser la méthode corrigée pour l'authentification
            $authenticatedUser = $this->getAuthenticatedUser();
            $userId = $authenticatedUser ? $authenticatedUser->id : null;
            
            // Log pour debug
            Log::info("Scan - User authenticated: " . ($userId ? "Yes (ID: $userId)" : "No"));

            $scan = ScanResult::create([
                'scan_id' => Str::uuid(),
                'url' => $fullUrl,  // Stocker l'URL complète dans la base de données
                'status' => 'pending',
                'user_id' => $userId // CORRECTION: Utiliser l'ID correct
            ]);
            
            // Lancer le job avec l'URL nettoyée pour les outils
            ScanWebsite::dispatch($cleanUrl, $scan->scan_id)->delay(now()->addSeconds(2));
            
            Log::info("Scan started for URL: {$fullUrl}, Clean URL: {$cleanUrl}, Scan ID: {$scan->scan_id}, User ID: " . ($userId ?? 'null'));
            
            return response()->json([
                'message' => 'Scan started',
                'scan_id' => $scan->scan_id,
                'url' => $fullUrl
            ], 202);
        } catch (\Exception $e) {
            Log::error("Error starting scan: " . $e->getMessage());
            
            return response()->json([
                'message' => 'Error starting scan',
                'error' => $e->getMessage()
            ], 500);
        }
    }

   public function getResults($scan_id)
{
    try {
        $scan = ScanResult::where('scan_id', $scan_id)->first();
        
        if (!$scan) {
            return response()->json(['message' => 'Scan not found.'], 404);
        }
        
        // Personnaliser les messages pour l'interface utilisateur
        $clientMessage = null;
        
        if ($scan->status === 'timeout') {
            $clientMessage = "Your scan is taking longer than expected. Please be patient, we're still working on it.";
        } elseif ($scan->status === 'failed') {
            $clientMessage = "We encountered an issue while scanning this website. We're attempting to resolve it. Please check back in a few minutes.";
        } elseif ($scan->status === 'running') {
            $clientMessage = "Your scan is in progress. This may take several minutes for complex websites. Please wait.";
        } elseif ($scan->status === 'completed') {
            $clientMessage = "Ta-da ! Your scan is completed, you can now check the results.";
        }
        // Retourner les résultats, incluant l'analyse Gemini si disponible
        return response()->json([
            'id' => $scan->scan_id,
            'scan_id' => $scan->scan_id,
            'url' => $scan->url,
            'status' => $scan->status ?? 'unknown',
            'created_at' => $scan->created_at,
            'whatweb_output' => $scan->whatweb_output,
            'sslyze_output' => $scan->sslyze_output,
            'zap_output' => $scan->zap_output,
            'error' => $scan->error,
            'gemini_analysis' => $scan->gemini_analysis,
            'user_message' => $clientMessage
        ]);
    } catch (\Exception $e) {
        Log::error("Error retrieving scan results: " . $e->getMessage());
        
        return response()->json([
            'message' => 'Error retrieving scan results',
            'error' => $e->getMessage(),
            'user_message' => "We're experiencing some technical difficulties. Please try again later."
        ], 500);
    }
}

    public function searchScans(Request $request)
    {   
        // Accepter soit 'q' soit 'url' comme paramètre
        $query = $request->input('q') ?? $request->input('url');
        
        // CORRECTION: Permettre la recherche sans query pour récupérer les scans récents
        if (empty($query)) {
            // Si pas de query, retourner les scans récents
            try {
                $authenticatedUser = $this->getAuthenticatedUser();
                
                $scansQuery = ScanResult::orderBy('created_at', 'desc')->limit(20);
                
                // Si l'utilisateur est connecté, prioriser ses scans
                if ($authenticatedUser) {
                    $scansQuery->where(function($q) use ($authenticatedUser) {
                        $q->where('user_id', $authenticatedUser->id)
                          ->orWhereNull('user_id'); // Inclure aussi les scans sans user_id
                    });
                }
                
                $scans = $scansQuery->get(['scan_id', 'url', 'status', 'created_at']);
                
                $formattedScans = $scans->map(function($scan) {
                    return [
                        'id' => $scan->scan_id,
                        'scan_id' => $scan->scan_id,
                        'url' => $scan->url,
                        'status' => $scan->status ?? 'unknown',
                        'created_at' => $scan->created_at
                    ];
                });
                
                return response()->json($formattedScans);
            } catch (\Exception $e) {
                Log::error("Error retrieving recent scans: " . $e->getMessage());
                return response()->json([
                    'message' => 'Error retrieving recent scans',
                    'error' => $e->getMessage()
                ], 500);
            }
        }
        
        try {
            // Recherche à la fois par URL exacte et par pattern de recherche
            $authenticatedUser = $this->getAuthenticatedUser();
            
            $scansQuery = ScanResult::where(function($q) use ($query) {
                            $q->where('url', 'like', '%' . $query . '%')
                              ->orWhere('url', 'like', '%https://' . $query . '%')
                              ->orWhere('url', 'like', '%http://' . $query . '%');
                        });
            
            // CORRECTION: Utiliser la méthode corrigée pour l'authentification
            if ($authenticatedUser) {
                $scansQuery->where(function($q) use ($authenticatedUser) {
                    $q->where('user_id', $authenticatedUser->id)
                      ->orWhereNull('user_id'); // Inclure aussi les scans sans user_id
                });
            }
            
            $scans = $scansQuery->orderBy('created_at', 'desc')
                              ->limit(10)
                              ->get(['scan_id', 'url', 'status', 'created_at']);
            
            // Transformer les résultats pour qu'ils correspondent à l'interface ScanResult
            $formattedScans = $scans->map(function($scan) {
                return [
                    'id' => $scan->scan_id, // Ajout de l'id pour compatibilité avec le frontend
                    'scan_id' => $scan->scan_id,
                    'url' => $scan->url,
                    'status' => $scan->status ?? 'unknown',
                    'created_at' => $scan->created_at
                ];
            });
            
            return response()->json($formattedScans);
        } catch (\Exception $e) {
            Log::error("Error searching scans: " . $e->getMessage());
            
            return response()->json([
                'message' => 'Error searching scans',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function getUserScans(Request $request)
    {
        // CORRECTION: Utiliser la méthode corrigée pour l'authentification
        $authenticatedUser = $this->getAuthenticatedUser();
        
        if (!$authenticatedUser) {
            return response()->json([
                'message' => 'User not authenticated',
            ], 401);
        }
        
        try {
            $limit = $request->input('limit', 10);
            
            // CORRECTION: Inclure les scans avec user_id ET ceux avec user_id NULL
            $scans = ScanResult::where(function($query) use ($authenticatedUser) {
                        $query->where('user_id', $authenticatedUser->id)
                              ->orWhereNull('user_id'); // Inclure les anciens scans
                    })
                    ->orderBy('created_at', 'desc')
                    ->limit($limit)
                    ->get(['scan_id', 'url', 'status', 'created_at']);
            
            // Transformer les résultats pour qu'ils correspondent à l'interface ScanResult
            $formattedScans = $scans->map(function($scan) {
                return [
                    'id' => $scan->scan_id, // Ajout de l'id pour compatibilité avec le frontend
                    'scan_id' => $scan->scan_id,
                    'url' => $scan->url,
                    'status' => $scan->status ?? 'unknown',
                    'created_at' => $scan->created_at
                ];
            });
            
            return response()->json($formattedScans);
        } catch (\Exception $e) {
            Log::error("Error retrieving user scans: " . $e->getMessage());
            
            return response()->json([
                'message' => 'Error retrieving user scans',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * API pour régénérer manuellement un rapport via Gemini
     */
    public function generateReport(Request $request)
    {
        // Récupérer l'ID du scan pour lequel générer un rapport
        $scan_id = $request->input('scan_id');
        
        if (empty($scan_id)) {
            return response()->json([
                'message' => 'Scan ID is required',
            ], 400);
        }
        
        try {
            // Récupérer les données du scan
            $scan = ScanResult::where('scan_id', $scan_id)->first();
            
            if (!$scan) {
                return response()->json(['message' => 'Scan not found.'], 404);
            }
            
            // Vérifier que le scan est bien terminé
            if ($scan->status !== 'completed') {
                return response()->json([
                    'message' => 'Cannot generate report. Scan is not completed.',
                    'status' => $scan->status
                ], 400);
            }
            
            // Créer un nouveau job pour générer le rapport
            ScanWebsite::dispatch($scan->url, $scan->scan_id)->delay(now());
            
            return response()->json([
                'success' => true,
                'message' => 'Regeneration of analysis requested',
                'scan_id' => $scan_id,
                'url' => $scan->url
            ]);
            
        } catch (\Exception $e) {
            Log::error("Error generating report: " . $e->getMessage());
            
            return response()->json([
                'message' => 'Error generating report',
                'error' => $e->getMessage()
            ], 500);
        }
    }
}