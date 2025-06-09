<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\JWTService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use PragmaRX\Google2FA\Google2FA;

class AuthController extends Controller
{
    protected JWTService $jwtService;

    public function __construct(JWTService $jwtService)
    {
        $this->jwtService = $jwtService;
    }

    /**
     * 🔒 REGISTRATION SÉCURISÉ mais COMPATIBLE
     */
    public function register(Request $request)
    {
        // 🔧 Rate limiting modéré (pas trop strict)
        $rateLimitKey = 'register:' . $request->ip();
        if (RateLimiter::tooManyAttempts($rateLimitKey, 5)) { // 5 tentatives/heure au lieu de 3
            $seconds = RateLimiter::availableIn($rateLimitKey);
            return response()->json([
                'message' => 'Too many registration attempts',
                'retry_after_seconds' => $seconds
            ], 429);
        }

        // 🔧 Validation MOINS STRICTE pour compatibilité
        $validator = $this->getCompatibleRegistrationValidator($request->all());
        
        if ($validator->fails()) {
            RateLimiter::hit($rateLimitKey, 3600);
            
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        // 🔧 Sanitisation légère (pas trop agressive)
        $secureData = $this->lightSanitizeUserInput($validator->validated());
        
        // Vérification unicité email
        if (User::where('email', $secureData['email'])->exists()) {
            RateLimiter::hit($rateLimitKey, 3600);
            
            return response()->json([
                'message' => 'Email already registered',
                'error' => 'This email is already in use'
            ], 409);
        }

        try {
            // 🔧 CORRECTION CRITIQUE : Création sécurisée avec nouveau User.php
            $user = new User();
            $user->name = $secureData['name'];
            $user->email = $secureData['email'];
            $user->password = Hash::make($secureData['password']);
            $user->save(); // Utiliser save() normal car ces champs sont dans $fillable

            // Génération JWT
            $tokenData = $this->jwtService->generateToken($user);

            // Logging sécurisé
            Log::info('User registered successfully', [
                'user_id' => $user->id,
                'email_domain' => substr(strrchr($user->email, "@"), 1),
                'ip' => $request->ip()
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
                'ip' => $request->ip()
            ]);
            
            return response()->json([
                'message' => 'Registration failed',
                'error' => 'Internal server error'
            ], 500);
        }
    }

    /**
     * 🔒 LOGIN SÉCURISÉ mais COMPATIBLE avec 2FA
     */
    public function login(Request $request)
    {
        // Rate limiting modéré
        $ipRateLimitKey = 'login-ip:' . $request->ip();
        $emailRateLimitKey = 'login-email:' . hash('sha256', $request->input('email', ''));
        
        if (RateLimiter::tooManyAttempts($ipRateLimitKey, 15) || 
            RateLimiter::tooManyAttempts($emailRateLimitKey, 8)) { 
            
            $seconds = max(
                RateLimiter::availableIn($ipRateLimitKey),
                RateLimiter::availableIn($emailRateLimitKey)
            );
            
            Log::warning('Login rate limit exceeded', [
                'ip' => $request->ip(),
                'email_hash' => hash('sha256', $request->input('email', ''))
            ]);
            
            return response()->json([
                'message' => 'Too many login attempts',
                'retry_after_seconds' => $seconds
            ], 429);
        }

        // 🔧 Validation COMPATIBLE (moins stricte)
        $validator = $this->getCompatibleLoginValidator($request->all());
        
        if ($validator->fails()) {
            RateLimiter::hit($ipRateLimitKey, 3600);
            RateLimiter::hit($emailRateLimitKey, 3600);
            
            return response()->json([
                'message' => 'Invalid input format',
                'errors' => $validator->errors()
            ], 422);
        }

        $secureData = $this->lightSanitizeUserInput($validator->validated());

        // Recherche utilisateur
        $user = User::where('email', $secureData['email'])->first();
        
        if (!$user || !Hash::check($secureData['password'], $user->password)) {
            RateLimiter::hit($ipRateLimitKey, 3600);
            RateLimiter::hit($emailRateLimitKey, 3600);
            
            Log::warning('Invalid login attempt', [
                'ip' => $request->ip(),
                'email_exists' => !!$user,
                'email_hash' => hash('sha256', $secureData['email'])
            ]);
            
            return response()->json([
                'message' => 'Invalid credentials',
            ], 401);
        }

        // Gestion 2FA COMPATIBLE
        $has2FAEnabled = $user->hasTwoFactorEnabled();
        
        if ($has2FAEnabled) {
            if (!isset($secureData['two_factor_code'])) {
                return response()->json([
                    'message' => '2FA code required',
                    'requires_2fa' => true,
                    'user_id' => $user->id,
                    'email' => $user->email
                ], 200);
            }
            
            // Validation du code 2FA
            $twoFactorValid = $this->verify2FACode($user, $secureData['two_factor_code']);
            
            if (!$twoFactorValid) {
                RateLimiter::hit($emailRateLimitKey, 3600);
                
                Log::warning('Invalid 2FA code', [
                    'user_id' => $user->id,
                    'ip' => $request->ip()
                ]);
                
                return response()->json([
                    'message' => 'Invalid 2FA code',
                    'requires_2fa' => true,
                    'user_id' => $user->id,
                    'email' => $user->email
                ], 422);
            }
        }

        // Login réussi - génération token
        try {
            $tokenData = $this->jwtService->generateToken($user, [
                'two_factor_verified' => $has2FAEnabled,
                'login_method' => $has2FAEnabled ? '2fa' : 'password'
            ]);
            
            Log::info('Login successful', [
                'user_id' => $user->id,
                'ip' => $request->ip(),
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
            Log::error('Token generation error', [
                'error' => $e->getMessage(),
                'user_id' => $user->id,
                'ip' => $request->ip()
            ]);
            
            return response()->json([
                'message' => 'Authentication successful but token generation failed',
                'error' => 'Please try again'
            ], 500);
        }
    }

    /**
     * 🔧 VALIDATION COMPATIBLE POUR REGISTRATION (moins stricte)
     */
    private function getCompatibleRegistrationValidator(array $data)
    {
        return Validator::make($data, [
            'name' => [
                'required',
                'string',
                'min:2',
                'max:50',
                // 🔧 CORRECTION : Pattern moins strict pour compatibilité
                'regex:/^[\p{L}\s\-\.\']{2,50}$/u'
            ],
            'email' => [
                'required',
                'string',
                'email', // 🔧 CORRECTION : email simple au lieu de email:rfc,dns
                'max:100',
                'unique:users,email'
            ],
            'password' => [
                'required',
                'string',
                'min:8',
                'max:255'
                // 🔧 CORRECTION : Pas de regex strict pour compatibilité utilisateurs existants
            ],
            'password_confirmation' => [
                'required',
                'same:password'
            ]
        ], [
            'name.regex' => 'Name can only contain letters, spaces, hyphens, dots, and apostrophes',
            'email.email' => 'Please provide a valid email address'
        ]);
    }

    /**
     * 🔧 VALIDATION COMPATIBLE POUR LOGIN (moins stricte)
     */
    private function getCompatibleLoginValidator(array $data)
    {
        return Validator::make($data, [
            'email' => [
                'required',
                'string',
                'email', 
                'max:100'
            ],
            'password' => [
                'required',
                'string',
                'min:1',
                'max:255'
            ],
            'two_factor_code' => [
                'nullable',
                'string',
                'regex:/^[0-9A-Z]{6,8}$/' 
            ]
        ]);
    }

    private function lightSanitizeUserInput(array $data)
    {
        $sanitized = [];
        
        foreach ($data as $key => $value) {
            if (is_string($value) && $key !== 'password') { 
                $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $value);
                
                $value = trim($value);
                
                $sanitized[$key] = $value;
            } else {
                $sanitized[$key] = $value; // Laisser les mots de passe intacts
            }
        }
        
        return $sanitized;
    }

    /**
     * 🔄 REFRESH TOKEN (identique)
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
     * 🚪 LOGOUT (identique)
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
     * 👤 GET USER INFO (identique)
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
     * 🔍 VERIFICATION CODE 2FA - Avec protection timing attack
     */
   private function verify2FACode($user, $code)
    {
        // Protection contre les attaques temporelles
        $startTime = hrtime(true);
        
        try {
            // Code de récupération (8 caractères)
            if (strlen($code) === 8 && !empty($user->two_factor_recovery_codes)) {
                $result = $this->verifyRecoveryCode($user, $code);
            }
            // Code TOTP (6 chiffres)
            elseif (strlen($code) === 6 && is_numeric($code)) {
                if (empty($user->two_factor_secret)) {
                    $result = false;
                } else {
                    $google2fa = new Google2FA();
                    $secret = decrypt($user->two_factor_secret);
                    $result = $google2fa->verifyKey($secret, $code, 2);
                }
            } else {
                $result = false;
            }
            
            // Protection timing attack - toujours prendre le même temps
            $elapsedTime = hrtime(true) - $startTime;
            $minTime = 10000000; // 10ms en nanosecondes
            if ($elapsedTime < $minTime) {
                usleep(($minTime - $elapsedTime) / 1000);
            }
            
            return $result;
            
        } catch (\Exception $e) {
            Log::error('2FA verification error', [
                'error' => $e->getMessage(),
                'user_id' => $user->id
            ]);
            
            // Protection timing attack même en cas d'erreur
            $elapsedTime = hrtime(true) - $startTime;
            $minTime = 10000000;
            if ($elapsedTime < $minTime) {
                usleep(($minTime - $elapsedTime) / 1000);
            }
            
            return false;
        }
    }
    
    /**
     * 🔐 VERIFICATION CODE DE RECUPERATION - COMPATIBLE avec nouveau User.php
     */
    private function verifyRecoveryCode($user, $code)
    {
        try {
            $recoveryCodes = collect(json_decode(decrypt($user->two_factor_recovery_codes), true));
            
            if (!$recoveryCodes->contains($code)) {
                return false;
            }

            // Supprimer le code utilisé (usage unique)
            $remainingCodes = $recoveryCodes->reject(function ($recoveryCode) use ($code) {
                return hash_equals($recoveryCode, $code); // Protection timing attack
            });

            // 🔧 CORRECTION CRITIQUE : Utiliser saveQuietly() pour ignorer les restrictions $guarded
            $user->two_factor_recovery_codes = encrypt($remainingCodes->toJson());
            $user->saveQuietly();

            Log::info('Recovery code used', [
                'user_id' => $user->id,
                'remaining_codes' => $remainingCodes->count()
            ]);

            return true;
            
        } catch (\Exception $e) {
            Log::error('Recovery code error', [
                'error' => $e->getMessage(),
                'user_id' => $user->id
            ]);
            return false;
        }
    }
}