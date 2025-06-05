<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\JWTService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;
use PragmaRX\Google2FA\Google2FA;

class AuthController extends Controller
{
    protected JWTService $jwtService;

    public function __construct(JWTService $jwtService)
    {
        $this->jwtService = $jwtService;
    }

    /**
     * 📝 REGISTRATION - Simplifié
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ]);
    
        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }
    
        try {
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);
    
            // Générer JWT
            $tokenData = $this->jwtService->generateToken($user);
    
            Log::info('User registered successfully', [
                'user_id' => $user->id,
                'email' => $user->email
            ]);

            return response()->json([
                'message' => 'User registered successfully',
                'user' => $tokenData['user'],
                'access_token' => $tokenData['access_token'],
                'refresh_token' => $tokenData['refresh_token'],
                'token_type' => $tokenData['token_type'],
                'expires_in' => $tokenData['expires_in'],
            ]);
        } catch (\Exception $e) {
            Log::error('Registration error', [
                'error' => $e->getMessage(),
                'email' => $request->email
            ]);
            
            return response()->json([
                'message' => 'An error occurred while creating the user.',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * 🔐 LOGIN AVEC 2FA SIMPLIFIÉ - Tout en une seule méthode
     */
    public function login(Request $request)
    {
        Log::info('🔐 LOGIN ATTEMPT START', [
            'email' => $request->email,
            'has_2fa_code' => !empty($request->two_factor_code),
            'ip' => $request->ip()
        ]);

        // Validation des entrées
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
            'two_factor_code' => 'nullable|string'
        ]);
    
        // Recherche utilisateur
        $user = User::where('email', $request->email)->first();
        
        if (!$user || !Hash::check($request->password, $user->password)) {
            Log::warning('🔐 INVALID CREDENTIALS', [
                'email' => $request->email,
                'user_exists' => !!$user
            ]);
            
            return response()->json([
                'message' => 'Invalid credentials',
            ], 401);
        }

        // Vérifier le statut 2FA
        $has2FAEnabled = $user->hasTwoFactorEnabled();
        
        Log::info('🔐 2FA CHECK', [
            'user_id' => $user->id,
            'has_2fa_enabled' => $has2FAEnabled,
            'code_provided' => !empty($request->two_factor_code)
        ]);

        // Si 2FA activé
        if ($has2FAEnabled) {
            // Si pas de code fourni, demander le code
            if (!$request->two_factor_code) {
                Log::info('🔐 2FA REQUIRED - NO CODE PROVIDED');
                
                return response()->json([
                    'message' => '2FA code required',
                    'requires_2fa' => true,
                    'user_id' => $user->id,
                    'email' => $user->email // Pour simplifier côté frontend
                ], 200);
            }
            
            // Vérifier le code 2FA
            Log::info('🔐 VERIFYING 2FA CODE', [
                'code_length' => strlen($request->two_factor_code)
            ]);
            
            $twoFactorValid = $this->verify2FACode($user, $request->two_factor_code);
            
            if (!$twoFactorValid) {
                Log::warning('🔐 INVALID 2FA CODE', [
                    'user_id' => $user->id
                ]);
                
                return response()->json([
                    'message' => 'Invalid 2FA code',
                    'requires_2fa' => true,
                    'user_id' => $user->id,
                    'email' => $user->email
                ], 422);
            }
            
            Log::info('🔐 2FA CODE VALID');
        }

        // ✅ CONNEXION RÉUSSIE - Générer les tokens
        try {
            $tokenData = $this->jwtService->generateToken($user, [
                'two_factor_verified' => $has2FAEnabled // Marquer si 2FA était requis et validé
            ]);
            
            Log::info('🔐 LOGIN SUCCESSFUL', [
                'user_id' => $user->id,
                'email' => $user->email,
                'two_factor_used' => $has2FAEnabled
            ]);
        
            return response()->json([
                'message' => 'Successfully logged in',
                'user' => $tokenData['user'],
                'access_token' => $tokenData['access_token'],
                'refresh_token' => $tokenData['refresh_token'],
                'token_type' => $tokenData['token_type'],
                'expires_in' => $tokenData['expires_in'],
            ]);
            
        } catch (\Exception $e) {
            Log::error('🔐 TOKEN GENERATION ERROR', [
                'error' => $e->getMessage(),
                'user_id' => $user->id
            ]);
            
            return response()->json([
                'message' => 'Authentication successful but token generation failed',
                'error' => 'Please try again'
            ], 500);
        }
    }

    /**
     * 🔄 REFRESH TOKEN
     */
    public function refresh(Request $request)
    {
        $request->validate([
            'refresh_token' => 'required|string'
        ]);

        try {
            $tokenData = $this->jwtService->refreshToken($request->refresh_token);

            if (!$tokenData) {
                return response()->json([
                    'message' => 'Invalid refresh token'
                ], 401);
            }

            Log::info('🔄 TOKEN REFRESHED', [
                'user_id' => $tokenData['user']['id'] ?? 'unknown'
            ]);

            return response()->json($tokenData);
            
        } catch (\Exception $e) {
            Log::error('🔄 REFRESH ERROR', [
                'error' => $e->getMessage()
            ]);
            
            return response()->json([
                'message' => 'Failed to refresh token'
            ], 401);
        }
    }
    
    /**
     * 🚪 LOGOUT
     */
    public function logout(Request $request)
    {
        $token = $request->bearerToken();
        
        if (!$token) {
            return response()->json(['message' => 'No token provided'], 400);
        }

        try {
            $revoked = $this->jwtService->revokeToken($token);
            
            if ($revoked) {
                Log::info('🚪 USER LOGGED OUT', [
                    'ip' => $request->ip(),
                    'user_agent' => $request->userAgent()
                ]);
                
                return response()->json(['message' => 'Logged out successfully']);
            } else {
                return response()->json(['message' => 'Failed to logout'], 500);
            }
        } catch (\Exception $e) {
            Log::error('🚪 LOGOUT ERROR', [
                'error' => $e->getMessage()
            ]);
            
            return response()->json(['message' => 'Logout failed'], 500);
        }
    }

    /**
     * 👤 GET USER INFO
     */
    public function me(Request $request)
    {
        try {
            $payload = $request->attributes->get('jwt_payload');
            
            if (!$payload) {
                return response()->json([
                    'message' => 'JWT payload missing',
                    'error' => 'Invalid token'
                ], 401);
            }
            
            if (!isset($payload->user)) {
                return response()->json([
                    'message' => 'User data missing in token',
                    'error' => 'Malformed token'
                ], 401);
            }
            
            return response()->json([
                'success' => true,
                'user' => $payload->user,
                'security' => $payload->security ?? null,
                'quotas' => $payload->quotas ?? null,
                'expires_at' => date('c', $payload->exp),
                'issued_at' => date('c', $payload->iat)
            ]);
            
        } catch (\Exception $e) {
            Log::error('👤 ME ERROR', [
                'error' => $e->getMessage()
            ]);
            
            return response()->json([
                'message' => 'Error retrieving user information',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * 🔍 VERIFICATION CODE 2FA - Méthode privée
     */
    private function verify2FACode($user, $code)
    {
        Log::info('🔍 VERIFY 2FA CODE START', [
            'user_id' => $user->id,
            'code_length' => strlen($code),
            'code_type' => strlen($code) > 6 ? 'recovery' : 'totp'
        ]);

        try {
            // Code de récupération (plus de 6 caractères)
            if (strlen($code) > 6 && !empty($user->two_factor_recovery_codes)) {
                Log::info('🔍 CHECKING RECOVERY CODE');
                return $this->verifyRecoveryCode($user, $code);
            }
            
            // Code TOTP normal (6 chiffres)
            if (strlen($code) === 6 && is_numeric($code)) {
                Log::info('🔍 CHECKING TOTP CODE');
                
                if (empty($user->two_factor_secret)) {
                    Log::error('🔍 NO 2FA SECRET FOUND');
                    return false;
                }
                
                $google2fa = new Google2FA();
                $secret = decrypt($user->two_factor_secret);
                $isValid = $google2fa->verifyKey($secret, $code, 2); // 2 fenêtres de tolérance
                
                Log::info('🔍 TOTP VERIFICATION RESULT', ['valid' => $isValid]);
                return $isValid;
            }
            
            Log::warning('🔍 INVALID CODE FORMAT', [
                'length' => strlen($code),
                'is_numeric' => is_numeric($code)
            ]);
            return false;
            
        } catch (\Exception $e) {
            Log::error('🔍 2FA VERIFICATION ERROR', [
                'error' => $e->getMessage(),
                'user_id' => $user->id
            ]);
            return false;
        }
    }
    
    /**
     * 🔐 VERIFICATION CODE DE RECUPERATION - Méthode privée
     */
    private function verifyRecoveryCode($user, $code)
    {
        try {
            $recoveryCodes = collect(json_decode(decrypt($user->two_factor_recovery_codes), true));
            
            if (!$recoveryCodes->contains($code)) {
                Log::info('🔐 RECOVERY CODE NOT FOUND');
                return false;
            }

            // Supprimer le code utilisé (usage unique)
            $remainingCodes = $recoveryCodes->reject(function ($recoveryCode) use ($code) {
                return $recoveryCode === $code;
            });

            $user->update([
                'two_factor_recovery_codes' => encrypt($remainingCodes->toJson())
            ]);

            Log::info('🔐 RECOVERY CODE USED', [
                'user_id' => $user->id,
                'remaining_codes' => $remainingCodes->count()
            ]);

            return true;
            
        } catch (\Exception $e) {
            Log::error('🔐 RECOVERY CODE ERROR', [
                'error' => $e->getMessage(),
                'user_id' => $user->id
            ]);
            return false;
        }
    }
}