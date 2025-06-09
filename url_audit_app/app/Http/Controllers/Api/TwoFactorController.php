<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Collection;
use PragmaRX\Google2FA\Google2FA;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;

class TwoFactorController extends Controller
{
    protected $google2fa;

    public function __construct()
    {
        $this->google2fa = new Google2FA();
    }

    private function getAuthenticatedUser(Request $request)
    {
        $payload = $request->attributes->get('jwt_payload');
        
        if (!$payload) {
            Log::warning('JWT Payload missing in TwoFactorController', [
                'path' => $request->path(),
                'method' => $request->method()
            ]);
            return null;
        }
        
        $user = User::find($payload->sub);
        
        if (!$user) {
            Log::warning('User not found in database', [
                'user_id' => $payload->sub,
                'path' => $request->path()
            ]);
            return null;
        }
        
        return $user;
    }

    public function getStatus(Request $request)
    {
        try {
            $user = $this->getAuthenticatedUser($request);
            
            if (!$user) {
                return response()->json(['message' => 'User not authenticated'], 401);
            }

            Log::info('2FA Status requested', [
                'user_id' => $user->id,
                'email' => $user->email,
                'current_2fa_status' => $user->two_factor_enabled ?? false
            ]);

            return response()->json([
                'enabled' => $user->two_factor_enabled ?? false,
                'confirmed_at' => $user->two_factor_confirmed_at,
                'has_recovery_codes' => !empty($user->two_factor_recovery_codes)
            ]);

        } catch (\Exception $e) {
            Log::error('2FA Status Error: ' . $e->getMessage());
            return response()->json([
                'message' => 'Error getting 2FA status',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function generateSecret(Request $request)
    {
        try {
            $user = $this->getAuthenticatedUser($request);
            
            if (!$user) {
                return response()->json(['message' => 'User not authenticated'], 401);
            }

            // Vérifier le mot de passe avant de générer le secret
            $request->validate([
                'password' => 'required|string'
            ]);

            if (!Hash::check($request->password, $user->password)) {
                return response()->json([
                    'message' => 'Invalid password'
                ], 422);
            }

            $secret = $this->google2fa->generateSecretKey();
            

            $user->two_factor_secret = encrypt($secret);
            $user->two_factor_enabled = false;
            $user->two_factor_confirmed_at = null;
            $user->saveQuietly(); 

            // Générer l'URL pour Google Authenticator
            $qrCodeUrl = $this->google2fa->getQRCodeUrl(
                config('app.name', '3713 CyberSecurity'),
                $user->email,
                $secret
            );

            // Générer le QR code SVG
            $renderer = new ImageRenderer(
                new RendererStyle(200),
                new SvgImageBackEnd()
            );
            $writer = new Writer($renderer);
            $qrCodeSvg = $writer->writeString($qrCodeUrl);

            Log::info('2FA Secret generated', [
                'user_id' => $user->id,
                'email' => $user->email
            ]);

            return response()->json([
                'secret' => $secret,
                'qr_code' => base64_encode($qrCodeSvg),
                'backup_codes' => $this->generateRecoveryCodes()
            ]);

        } catch (\Exception $e) {
            Log::error('2FA Secret Generation Error: ' . $e->getMessage());
            return response()->json([
                'message' => 'Error generating 2FA secret',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * ✅ Confirmer et activer l'A2F - COMPATIBLE avec nouveau User.php
     */
    public function confirmTwoFactor(Request $request)
    {
        try {
            $user = $this->getAuthenticatedUser($request);
            
            if (!$user || !$user->two_factor_secret) {
                return response()->json(['message' => 'No 2FA secret found'], 400);
            }

            $request->validate([
                'code' => 'required|string|size:6'
            ]);

            $secret = decrypt($user->two_factor_secret);
            
            // Vérifier le code A2F (avec tolérance de 60 secondes)
            $isValid = $this->google2fa->verifyKey($secret, $request->code, 2);

            if (!$isValid) {
                return response()->json([
                    'message' => 'Invalid 2FA code'
                ], 422);
            }

            // Générer et sauvegarder les codes de récupération
            $recoveryCodes = $this->generateRecoveryCodes();
            
            // 🔧 CORRECTION CRITIQUE : Utiliser enableTwoFactor() ou assignation directe + saveQuietly()
            $user->two_factor_enabled = true;
            $user->two_factor_confirmed_at = now();
            $user->two_factor_recovery_codes = encrypt($recoveryCodes->toJson());
            $user->saveQuietly(); // 🔧 Ignore les restrictions $guarded

            Log::info("2FA enabled for user: {$user->email}");

            return response()->json([
                'message' => '2FA activated successfully',
                'backup_codes' => $recoveryCodes,
                'enabled' => true
            ]);

        } catch (\Exception $e) {
            Log::error('2FA Confirmation Error: ' . $e->getMessage());
            return response()->json([
                'message' => 'Error confirming 2FA',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * ❌ Désactiver l'A2F - COMPATIBLE avec nouveau User.php
     */
    public function disableTwoFactor(Request $request)
    {
        try {
            $user = $this->getAuthenticatedUser($request);
            
            if (!$user) {
                return response()->json(['message' => 'User not authenticated'], 401);
            }

            $request->validate([
                'password' => 'required|string',
                'code' => 'required|string|size:6'
            ]);

            // Vérifier le mot de passe
            if (!Hash::check($request->password, $user->password)) {
                return response()->json(['message' => 'Invalid password'], 422);
            }

            // Vérifier le code A2F si activé
            if ($user->two_factor_enabled && $user->two_factor_secret) {
                $secret = decrypt($user->two_factor_secret);
                $isValid = $this->google2fa->verifyKey($secret, $request->code, 2);
                
                if (!$isValid) {
                    return response()->json(['message' => 'Invalid 2FA code'], 422);
                }
            }

            // 🔧 CORRECTION CRITIQUE : Utiliser assignation directe + saveQuietly()
            $user->two_factor_secret = null;
            $user->two_factor_recovery_codes = null;
            $user->two_factor_confirmed_at = null;
            $user->two_factor_enabled = false;
            $user->saveQuietly(); // 🔧 Ignore les restrictions $guarded

            Log::info("2FA disabled for user: {$user->email}");

            return response()->json([
                'message' => '2FA disabled successfully',
                'enabled' => false
            ]);

        } catch (\Exception $e) {
            Log::error('2FA Disable Error: ' . $e->getMessage());
            return response()->json([
                'message' => 'Error disabling 2FA',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * 🔄 Régénérer les codes de récupération - COMPATIBLE avec nouveau User.php
     */
    public function regenerateRecoveryCodes(Request $request)
    {
        try {
            $user = $this->getAuthenticatedUser($request);
            
            if (!$user || !$user->two_factor_enabled) {
                return response()->json(['message' => '2FA not enabled'], 400);
            }

            $request->validate([
                'password' => 'required|string'
            ]);

            if (!Hash::check($request->password, $user->password)) {
                return response()->json(['message' => 'Invalid password'], 422);
            }

            $recoveryCodes = $this->generateRecoveryCodes();
            
            // 🔧 CORRECTION CRITIQUE : Utiliser saveQuietly()
            $user->two_factor_recovery_codes = encrypt($recoveryCodes->toJson());
            $user->saveQuietly(); // 🔧 Ignore les restrictions $guarded

            Log::info('Recovery codes regenerated', [
                'user_id' => $user->id,
                'email' => $user->email
            ]);

            return response()->json([
                'backup_codes' => $recoveryCodes,
                'message' => 'Recovery codes regenerated successfully'
            ]);

        } catch (\Exception $e) {
            Log::error('Recovery Codes Regeneration Error: ' . $e->getMessage());
            return response()->json([
                'message' => 'Error regenerating recovery codes',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * 🔍 Vérifier un code A2F (pour le login)
     */
    public function verifyCode(Request $request)
    {
        try {
            $request->validate([
                'user_id' => 'required|integer',
                'code' => 'required|string'
            ]);

            $user = User::find($request->user_id);
            
            if (!$user || !$user->two_factor_enabled || !$user->two_factor_secret) {
                return response()->json(['message' => 'Invalid request'], 400);
            }

            $code = $request->code;
            
            // Vérifier si c'est un code de récupération (plus de 6 caractères)
            if (strlen($code) > 6) {
                return $this->verifyRecoveryCode($user, $code);
            }

            // Vérifier le code TOTP normal
            $secret = decrypt($user->two_factor_secret);
            $isValid = $this->google2fa->verifyKey($secret, $code, 2);

            if ($isValid) {
                Log::info('2FA code verified successfully', [
                    'user_id' => $user->id
                ]);

                return response()->json([
                    'valid' => true,
                    'message' => '2FA code verified successfully'
                ]);
            }

            return response()->json([
                'valid' => false,
                'message' => 'Invalid 2FA code'
            ], 422);

        } catch (\Exception $e) {
            Log::error('2FA Verification Error: ' . $e->getMessage());
            return response()->json([
                'message' => 'Error verifying 2FA code',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * 🛠️ Méthodes utilitaires privées
     */

    /**
     * Générer des codes de récupération
     */
    private function generateRecoveryCodes(): Collection
    {
        return collect(range(1, 8))->map(function () {
            return strtoupper(substr(str_replace(['+', '/', '='], '', base64_encode(random_bytes(6))), 0, 8));
        });
    }

    /**
     * Vérifier un code de récupération - COMPATIBLE avec nouveau User.php
     */
    private function verifyRecoveryCode(User $user, string $code)
    {
        if (empty($user->two_factor_recovery_codes)) {
            return response()->json([
                'valid' => false,
                'message' => 'No recovery codes available'
            ], 400);
        }

        $recoveryCodes = collect(json_decode(decrypt($user->two_factor_recovery_codes), true));
        
        if (!$recoveryCodes->contains($code)) {
            return response()->json([
                'valid' => false,
                'message' => 'Invalid recovery code'
            ], 422);
        }

        // Supprimer le code utilisé (usage unique)
        $remainingCodes = $recoveryCodes->reject(function ($recoveryCode) use ($code) {
            return $recoveryCode === $code;
        });

        // 🔧 CORRECTION CRITIQUE : Utiliser saveQuietly()
        $user->two_factor_recovery_codes = encrypt($remainingCodes->toJson());
        $user->saveQuietly(); // 🔧 Ignore les restrictions $guarded

        Log::info("Recovery code used for user: {$user->email}");

        return response()->json([
            'valid' => true,
            'message' => 'Recovery code verified successfully',
            'remaining_codes' => $remainingCodes->count()
        ]);
    }
}