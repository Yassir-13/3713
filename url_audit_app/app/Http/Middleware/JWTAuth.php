<?php
// app/Http/Middleware/JWTAuth.php - VERSION CORRIGÉE

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use App\Services\JWTService;
use Illuminate\Support\Facades\Log;

class JWTAuth
{
    protected JWTService $jwtService;

    public function __construct(JWTService $jwtService)
    {
        $this->jwtService = $jwtService;
    }

    public function handle(Request $request, Closure $next, ...$permissions)
    {
        try {
            // Récupérer le token Bearer
            $token = $request->bearerToken();
            
            if (!$token) {
                return response()->json([
                    'message' => 'Token manquant',
                    'error' => 'Authorization header requis'
                ], 401);
            }
            
            // Valider le token
            $payload = $this->jwtService->validateToken($token);
            
            if (!$payload) {
                return response()->json([
                    'message' => 'Token invalide ou expiré',
                    'error' => 'Veuillez vous reconnecter'
                ], 401);
            }
            
            if (!empty($permissions)) {
                $userPermissions = $this->extractUserPermissions($payload);
                
                Log::info('🔧 Permission Check Debug', [
                    'user_id' => $payload->sub ?? 'unknown',
                    'required_permissions' => $permissions,
                    'user_permissions' => $userPermissions,
                    'endpoint' => $request->path()
                ]);
                
                foreach ($permissions as $permission) {
                    if (!in_array($permission, $userPermissions)) {
                        Log::warning('PERMISSION DENIED', [
                            'user_id' => $payload->sub ?? 'unknown',
                            'required_permission' => $permission,
                            'user_permissions' => $userPermissions,
                            'endpoint' => $request->path()
                        ]);
                        
                        return response()->json([
                            'message' => 'Permission refusée',
                            'error' => "Autorisation '$permission' requise"
                        ], 403);
                    }
                }
            }
            
            //STOCKAGE SÉCURISÉ dans les attributes
            $request->attributes->set('jwt_payload', $payload);
            
            // Log pour audit
            Log::info('JWT AUTH SUCCESS', [
                'user_id' => $payload->sub ?? 'unknown',
                'endpoint' => $request->path(),
                'method' => $request->method(),
                'permissions_checked' => $permissions
            ]);
            
            return $next($request);
            
        } catch (\Firebase\JWT\ExpiredException $e) {
            Log::info('JWT Token Expired', ['ip' => $request->ip()]);
            return response()->json([
                'message' => 'Token expiré',
                'error' => 'Veuillez renouveler votre token ou vous reconnecter'
            ], 401);
            
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            Log::warning('JWT Invalid Signature', ['ip' => $request->ip()]);
            return response()->json([
                'message' => 'Signature de token invalide',
                'error' => 'Token compromis'
            ], 401);
            
        } catch (\Exception $e) {
            Log::error('JWT Middleware Error', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'ip' => $request->ip()
            ]);
            
            return response()->json([
                'message' => 'Authentication error',
                'error' => 'Internal authentication error'
            ], 500);
        }
    }

    /**
     * 🔧 NOUVELLE MÉTHODE : Extraction sécurisée des permissions
     */
    private function extractUserPermissions($payload): array
    {
        // Vérifications en cascade pour éviter les erreurs
        if (!isset($payload->security)) {
            Log::info('No security object in JWT payload', ['user_id' => $payload->sub ?? 'unknown']);
            return ['basic_scan']; // Permissions par défaut
        }
        
        if (!is_object($payload->security)) {
            Log::warning('Security is not an object in JWT payload', ['user_id' => $payload->sub ?? 'unknown']);
            return ['basic_scan'];
        }
        
        if (!isset($payload->security->scan_permissions)) {
            Log::info('No scan_permissions in JWT payload', ['user_id' => $payload->sub ?? 'unknown']);
            return ['basic_scan'];
        }
        
        if (!is_array($payload->security->scan_permissions)) {
            Log::warning('scan_permissions is not an array in JWT payload', ['user_id' => $payload->sub ?? 'unknown']);
            return ['basic_scan'];
        }
        
        return $payload->security->scan_permissions;
    }
}