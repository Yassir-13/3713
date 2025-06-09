<?php

namespace App\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use App\Models\User;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Carbon\Carbon;

class JWTService
{
    private string $secret;
    private string $algo;
    private int $ttl;
    private int $refreshTtl;

    public function __construct()
    {
        $this->secret = config('jwt.secret');
        $this->algo = config('jwt.algo', 'HS256');
        $this->ttl = config('jwt.ttl', 3600);
        $this->refreshTtl = config('jwt.refresh_ttl', 604800);
        
        if (empty($this->secret)) {
            throw new \Exception('JWT Secret not configured');
        }
    }

    /**
     * 🔧 CORRIGÉ : Génère un token JWT pour un utilisateur
     */
    public function generateToken(User $user, array $extraClaims = []): array
    {
        $now = Carbon::now();
        $issuedAt = $now->timestamp;
        $notBefore = $now->timestamp;
        $expiresAt = $now->copy()->addSeconds($this->ttl)->timestamp; 
        
        $jti = $this->generateJti();
        
        Log::info('🔧 Generating JWT Token', [
            'user_id' => $user->id,
            'jti' => $jti,
            'ttl' => $this->ttl,
            'issued_at' => date('Y-m-d H:i:s', $issuedAt),
            'expires_at' => date('Y-m-d H:i:s', $expiresAt)
        ]);
        
        // Payload principal (Access Token)
        $payload = [
            'iss' => config('app.name', '3713'),
            'aud' => '3713-users',
            'iat' => $issuedAt,
            'nbf' => $notBefore,   
            'exp' => $expiresAt,    
            'sub' => $user->id,
            'jti' => $jti,
            
            // Claims spécifiques à 3713
            'user' => [
                'id' => $user->id,
                'email' => $user->email,
                'name' => $user->name,
                'two_factor_enabled' => $user->two_factor_enabled ?? false,
            ],
            
            // Contexte sécurité
            'security' => array_merge([
                'two_factor_verified' => false,
                'last_login' => $now->toISOString(),
                'scan_permissions' => $this->getUserScanPermissions($user),
            ], $extraClaims),
            
            // Quotas et limites
            'quotas' => [
                'daily_scans' => 10,
                'concurrent_scans' => 2,
                'plan' => 'free',
            ]
        ];

        // 🔧 CORRECTION : Refresh Token avec timestamps séparés et corrects
        $refreshNow = Carbon::now(); // 🔧 NOUVEAU : Instance séparée pour refresh
        $refreshExpiresAt = $refreshNow->copy()->addSeconds($this->refreshTtl)->timestamp;
        
        $refreshPayload = [
            'iss' => config('app.name', '3713'),
            'aud' => '3713-refresh',
            'iat' => $refreshNow->timestamp,
            'exp' => $refreshExpiresAt,
            'sub' => $user->id,
            'jti' => $jti . '_refresh',
            'type' => 'refresh'
        ];

        $accessToken = JWT::encode($payload, $this->secret, $this->algo);
        $refreshToken = JWT::encode($refreshPayload, $this->secret, $this->algo);

        // Stocker les tokens dans le cache avec TTL correct
        $this->storeTokenId($jti, $user->id, $this->ttl);
        $this->storeTokenId($jti . '_refresh', $user->id, $this->refreshTtl);

        Log::info('JWT Tokens generated successfully', [
            'user_id' => $user->id,
            'access_expires_at' => date('Y-m-d H:i:s', $expiresAt),
            'refresh_expires_at' => date('Y-m-d H:i:s', $refreshExpiresAt)
        ]);

        return [
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'token_type' => 'Bearer',
            'expires_in' => $this->ttl,
            'user' => $payload['user']
        ];
    }

    /**
     * 🔧 CORRIGÉ : Valide et décode un token JWT avec logs détaillés
     */
    public function validateToken(string $token): ?object
    {
        try {
            $decoded = JWT::decode($token, new Key($this->secret, $this->algo));
            
            Log::debug('JWT Token decoded', [
                'jti' => $decoded->jti ?? 'missing',
                'sub' => $decoded->sub ?? 'missing',
                'exp' => isset($decoded->exp) ? date('Y-m-d H:i:s', $decoded->exp) : 'missing',
                'iat' => isset($decoded->iat) ? date('Y-m-d H:i:s', $decoded->iat) : 'missing', 
                'current_time' => date('Y-m-d H:i:s'), 
                'is_blacklisted' => $this->isTokenBlacklisted($decoded->jti ?? '')
            ]);
            
            // Vérifier si le token est blacklisté
            if (isset($decoded->jti) && $this->isTokenBlacklisted($decoded->jti)) {
                Log::info('Token blacklisted', ['jti' => $decoded->jti]);
                return null;
            }

            return $decoded;
            
        } catch (\Firebase\JWT\ExpiredException $e) {
            Log::info('JWT Token expired', ['error' => $e->getMessage()]);
            return null;
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            Log::warning('JWT Invalid signature', ['error' => $e->getMessage()]);
            return null;
        } catch (\Exception $e) {
            Log::error('JWT Validation error', [
                'error' => $e->getMessage(),
                'error_type' => get_class($e) 
            ]);
            return null;
        }
    }

    /**
     * 🔧 CORRIGÉ : Renouvelle un token avec le refresh token
     */
    public function refreshToken(string $refreshToken): ?array
    {
        try {
            Log::info('🔧 Attempting token refresh');
            
            // 🔧 CORRECTION : Validation temporelle explicite
            $currentTimestamp = Carbon::now()->timestamp;
            
            $decoded = JWT::decode($refreshToken, new Key($this->secret, $this->algo));
            
            Log::debug('Refresh token decoded', [
                'type' => $decoded->type ?? 'missing',
                'sub' => $decoded->sub ?? 'missing',
                'jti' => $decoded->jti ?? 'missing',
                'exp' => isset($decoded->exp) ? date('Y-m-d H:i:s', $decoded->exp) : 'missing',
                'iat' => isset($decoded->iat) ? date('Y-m-d H:i:s', $decoded->iat) : 'missing', // 🔧 AJOUTÉ
                'current_time' => date('Y-m-d H:i:s', $currentTimestamp) // 🔧 AJOUTÉ
            ]);
            
            // Vérifier que c'est bien un refresh token
            if (!isset($decoded->type) || $decoded->type !== 'refresh') {
                Log::warning('Not a refresh token', ['type' => $decoded->type ?? 'missing']);
                return null;
            }

            // 🔧 CORRECTION : Vérification d'expiration manuelle pour debug
            if (isset($decoded->exp) && $currentTimestamp > $decoded->exp) {
                Log::warning('Refresh token expired manually checked', [
                    'current' => $currentTimestamp,
                    'expires' => $decoded->exp,
                    'diff_seconds' => $currentTimestamp - $decoded->exp
                ]);
                return null;
            }

            // Vérifier si le token est blacklisté
            if (isset($decoded->jti) && $this->isTokenBlacklisted($decoded->jti)) {
                Log::info('Refresh token blacklisted', ['jti' => $decoded->jti]);
                return null;
            }

            // Récupérer l'utilisateur
            $user = User::find($decoded->sub);
            if (!$user) {
                Log::warning('User not found for refresh', ['user_id' => $decoded->sub]);
                return null;
            }

            // Blacklister l'ancien refresh token
            if (isset($decoded->jti)) {
                $this->blacklistToken($decoded->jti);
                Log::info('Old refresh token blacklisted', ['jti' => $decoded->jti]);
            }

            // 🔧 CORRECTION : Attendre 1 seconde pour éviter les problèmes de timing
            sleep(1);

            // Générer nouveaux tokens
            $newTokens = $this->generateToken($user);
            
            Log::info('✅ Token refresh successful', ['user_id' => $user->id]);
            
            return $newTokens;
            
        } catch (\Firebase\JWT\ExpiredException $e) {
            Log::info('Refresh token expired', [
                'error' => $e->getMessage(),
                'current_time' => date('Y-m-d H:i:s')
            ]);
            return null;
        } catch (\Exception $e) {
            Log::error('Token refresh error', [
                'error' => $e->getMessage(),
                'error_type' => get_class($e), // 🔧 AJOUTÉ
                'current_time' => date('Y-m-d H:i:s')
            ]);
            return null;
        }
    }

    /**
     * 🔧 CORRIGÉ : Révoque un token (logout) avec logs
     */
    public function revokeToken(string $token): bool
    {
        try {
            Log::info('🔧 Attempting token revocation');
            
            $decoded = JWT::decode($token, new Key($this->secret, $this->algo));
            
            if (isset($decoded->jti)) {
                $this->blacklistToken($decoded->jti);
                
                // Également blacklister le refresh token associé
                $refreshJti = $decoded->jti . '_refresh';
                $this->blacklistToken($refreshJti);
                
                Log::info('✅ Token revoked successfully', [
                    'jti' => $decoded->jti,
                    'refresh_jti' => $refreshJti,
                    'user_id' => $decoded->sub ?? 'unknown'
                ]);
                
                return true;
            }
            
            Log::warning('Token revocation failed - no JTI');
            return false;
            
        } catch (\Exception $e) {
            Log::error('Token revocation error', ['error' => $e->getMessage()]);
            return false;
        }
    }

    /**
     * Génère un identifiant unique pour le token
     */
    private function generateJti(): string
    {
        return uniqid('3713_', true) . '_' . bin2hex(random_bytes(16));
    }

    /**
     * Stocke l'ID du token pour pouvoir le révoquer
     */
    private function storeTokenId(string $jti, int $userId, int $ttl): void
    {
        Cache::put("jwt_token:{$jti}", $userId, $ttl);
        Log::debug('Token ID stored', ['jti' => $jti, 'user_id' => $userId, 'ttl' => $ttl]);
    }

    /**
     * Ajoute un token à la blacklist
     */
    private function blacklistToken(string $jti): void
    {
        Cache::put("jwt_blacklist:{$jti}", true, $this->refreshTtl);
        Log::debug('Token blacklisted', ['jti' => $jti]);
    }

    /**
     * Vérifie si un token est blacklisté
     */
    private function isTokenBlacklisted(string $jti): bool
    {
        return Cache::has("jwt_blacklist:{$jti}");
    }

    /**
     * Détermine les permissions de scan pour un utilisateur
     */
    private function getUserScanPermissions(User $user): array
    {
        $permissions = ['basic_scan']; // Permissions de base
        
        Log::debug('Computing user permissions', [
            'user_id' => $user->id,
            'two_factor_enabled' => $user->two_factor_enabled ?? false
        ]);

        // Si 2FA activé = plus de permissions
        if ($user->two_factor_enabled) {
            $permissions[] = 'advanced_scan';
            $permissions[] = 'export_reports';
        }

        Log::debug('User permissions computed', [
            'user_id' => $user->id,
            'permissions' => $permissions
        ]);

        return $permissions;
    }

    /**
     * 🔧 NOUVELLE MÉTHODE : Debugging des timestamps
     */
    public function debugTimestamps(): array
    {
        $now = Carbon::now();
        
        return [
            'current_time' => $now->toISOString(),
            'current_timestamp' => $now->timestamp,
            'ttl' => $this->ttl,
            'refresh_ttl' => $this->refreshTtl,
            'future_time' => $now->copy()->addSeconds($this->ttl)->toISOString(),
            'future_timestamp' => $now->copy()->addSeconds($this->ttl)->timestamp
        ];
    }
}