<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use PragmaRX\Google2FA\Google2FA;

class AuthController extends Controller
{
    /**
     * Handle user registration (inchangé)
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
    
            $token = $user->createToken('auth_token')->plainTextToken;
    
            return response()->json([
                'message' => 'User registered successfully',
                'user' => $user,
                'token' => $token,
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'An error occurred while creating the user.',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * 🔐 LOGIN AVEC A2F - VERSION DEBUG
     */
    public function login(Request $request)
    {
        Log::info('🐛 LOGIN ATTEMPT START', [
            'email' => $request->email,
            'has_2fa_code' => !empty($request->two_factor_code),
            'ip' => $request->ip()
        ]);

        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
            'two_factor_code' => 'nullable|string'
        ]);
    
        // Recherche de l'utilisateur
        $user = User::where('email', $request->email)->first();
        Log::info('🐛 USER FOUND', ['user_exists' => !!$user]);
    
        // Vérification credentials
        if (!$user || !Hash::check($request->password, $user->password)) {
            Log::warning('🐛 INVALID CREDENTIALS', [
                'email' => $request->email,
                'user_exists' => !!$user,
                'password_match' => $user ? Hash::check($request->password, $user->password) : false
            ]);
            
            return response()->json([
                'message' => 'Invalid credentials',
            ], 401);
        }

        // 🔍 DEBUG A2F - Afficher l'état complet de l'utilisateur
        $debugInfo = $user->debug2FAStatus();
        Log::info('🐛 USER 2FA DEBUG INFO', $debugInfo);

        // Vérifier si l'utilisateur a l'A2F activé
        $has2FAEnabled = $user->hasTwoFactorEnabled();
        Log::info('🐛 2FA CHECK RESULT', [
            'has_2fa_enabled' => $has2FAEnabled,
            'user_id' => $user->id
        ]);

        if ($has2FAEnabled) {
            Log::info('🐛 2FA IS REQUIRED');
            
            // Si aucun code A2F n'est fourni, demander le code
            if (!$request->two_factor_code) {
                Log::info('🐛 NO 2FA CODE PROVIDED - REQUESTING CODE');
                
                return response()->json([
                    'message' => '2FA code required',
                    'requires_2fa' => true,
                    'user_id' => $user->id
                ], 200);
            }
            
            Log::info('🐛 2FA CODE PROVIDED - VERIFYING', [
                'code_length' => strlen($request->two_factor_code)
            ]);
            
            // Vérifier le code A2F fourni
            $twoFactorValid = $this->verify2FACode($user, $request->two_factor_code);
            Log::info('🐛 2FA VERIFICATION RESULT', ['valid' => $twoFactorValid]);
            
            if (!$twoFactorValid) {
                Log::warning('🐛 INVALID 2FA CODE', [
                    'user_id' => $user->id,
                    'code_length' => strlen($request->two_factor_code)
                ]);
                
                return response()->json([
                    'message' => 'Invalid 2FA code',
                    'requires_2fa' => true,
                    'user_id' => $user->id
                ], 422);
            }
            
            Log::info('🐛 2FA CODE VALID - PROCEEDING TO LOGIN');
        } else {
            Log::info('🐛 2FA NOT REQUIRED - NORMAL LOGIN');
        }

        // 🎉 CONNEXION RÉUSSIE
        $token = $user->createToken('YourAppName')->plainTextToken;
        
        Log::info('🐛 LOGIN SUCCESSFUL', [
            'user_id' => $user->id,
            'email' => $user->email,
            'two_factor_used' => $has2FAEnabled
        ]);
    
        return response()->json([
            'message' => 'Successfully logged in',
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'two_factor_enabled' => $user->two_factor_enabled ?? false
            ],
            'token' => $token,
        ]);
    }
    
    /**
     * Handle user logout (inchangé)
     */
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        return response()->json(['message' => 'Logged out successfully']);
    }

    /**
     * 🔍 VÉRIFICATION CODE A2F - VERSION DEBUG
     */
    private function verify2FACode($user, $code)
    {
        Log::info('🐛 VERIFY 2FA CODE START', [
            'user_id' => $user->id,
            'code_length' => strlen($code),
            'code_type' => strlen($code) > 6 ? 'recovery' : 'totp'
        ]);

        try {
            // Code de récupération
            if (strlen($code) > 6 && !empty($user->two_factor_recovery_codes)) {
                Log::info('🐛 CHECKING RECOVERY CODE');
                return $this->verifyRecoveryCode($user, $code);
            }
            
            // Code TOTP normal
            if (strlen($code) === 6 && is_numeric($code)) {
                Log::info('🐛 CHECKING TOTP CODE');
                
                if (empty($user->two_factor_secret)) {
                    Log::error('🐛 NO 2FA SECRET FOUND');
                    return false;
                }
                
                $google2fa = new Google2FA();
                $secret = decrypt($user->two_factor_secret);
                $isValid = $google2fa->verifyKey($secret, $code, 2);
                
                Log::info('🐛 TOTP VERIFICATION RESULT', ['valid' => $isValid]);
                return $isValid;
            }
            
            Log::warning('🐛 INVALID CODE FORMAT', [
                'length' => strlen($code),
                'is_numeric' => is_numeric($code)
            ]);
            return false;
            
        } catch (\Exception $e) {
            Log::error('🐛 2FA VERIFICATION ERROR', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            return false;
        }
    }
    
    /**
     * Vérifier code de récupération
     */
    private function verifyRecoveryCode($user, $code)
    {
        try {
            $recoveryCodes = collect(json_decode(decrypt($user->two_factor_recovery_codes), true));
            
            if (!$recoveryCodes->contains($code)) {
                Log::info('🐛 RECOVERY CODE NOT FOUND');
                return false;
            }

            $remainingCodes = $recoveryCodes->reject(function ($recoveryCode) use ($code) {
                return $recoveryCode === $code;
            });

            $user->update([
                'two_factor_recovery_codes' => encrypt($remainingCodes->toJson())
            ]);

            Log::info('🐛 RECOVERY CODE USED', [
                'user_id' => $user->id,
                'remaining_codes' => $remainingCodes->count()
            ]);

            return true;
            
        } catch (\Exception $e) {
            Log::error('🐛 RECOVERY CODE ERROR', ['error' => $e->getMessage()]);
            return false;
        }
    }
}