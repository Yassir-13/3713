<?php
// app/Http/Middleware/JWTAuth.php

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
            
            // 🔧 CORRECTION : Vérifier les permissions avec accès sécurisé
            if (!empty($permissions)) {
                // Accès sécurisé aux propriétés avec vérifications
                $userPermissions = [];
                
                if (isset($payload->security) && 
                    is_object($payload->security) && 
                    isset($payload->security->scan_permissions) && 
                    is_array($payload->security->scan_permissions)) {
                    $userPermissions = $payload->security->scan_permissions;
                }
                
                Log::info('🔧 Permission Check Debug', [
                    'user_id' => $payload->sub ?? 'unknown',
                    'required_permissions' => $permissions,
                    'user_permissions' => $userPermissions,
                    'payload_security' => isset($payload->security) ? 'exists' : 'missing'
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
                            'error' => "Autorisation '$permission' requise",
                            'user_permissions' => $userPermissions // Debug info
                        ], 403);
                    }
                }
            }
            
            // ✅ STOCKAGE DANS LES ATTRIBUTES (pas dans le body de la requête)
            $request->attributes->set('jwt_payload', $payload);
            
            // Log pour audit avec accès sécurisé
            Log::info('🔑 JWT AUTH SUCCESS', [
                'user_id' => $payload->sub ?? 'unknown',
                'endpoint' => $request->path(),
                'method' => $request->method(),
                'permissions_checked' => $permissions,
                'two_factor_verified' => (isset($payload->security) && 
                                        isset($payload->security->two_factor_verified)) 
                    ? $payload->security->two_factor_verified 
                    : false
            ]);
            
            return $next($request);
            
        } catch (\Firebase\JWT\ExpiredException $e) {
            Log::info('JWT Token Expired', ['ip' => $request->ip()]);
            return response()->json([
                'message' => 'Token expiré',
                'error' => 'Veuillez renouveler votre token'
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
                'line' => $e->getLine(),
                'file' => $e->getFile(),
                'ip' => $request->ip()
            ]);
            
            return response()->json([
                'message' => 'Authentication error',
                'error' => 'Internal authentication error'
            ], 500);
        }
    }
}