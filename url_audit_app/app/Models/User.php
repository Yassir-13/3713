<?php

namespace App\Models;

use Illuminate\Support\Facades\Log;
use Laravel\Sanctum\HasApiTokens;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    /**
     * 🔒 SÉCURITÉ RENFORCÉE : Champs STRICTEMENT autorisés pour mass assignment
     * AUCUN champ sensible n'est inclus ici !
     */
    protected $fillable = [
        'name',
        'email',
        'password',
    ];
    protected $guarded = [
        'id',
        'email_verified_at',
        'remember_token',
        'created_at',
        'updated_at',
      
        'two_factor_secret',
        'two_factor_recovery_codes', 
        'two_factor_confirmed_at',
        'two_factor_enabled',
        
        'is_admin',
        'role',
        'permissions',
        'status',
        'email_verified_at',
        'api_token',
        'last_login_at',
        'login_count'
    ];
    protected $hidden = [
        'password',
        'remember_token',
        'two_factor_secret',
        'two_factor_recovery_codes',
    ];

    /**
     * 🔒 CASTING sécurisé des types
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
            'two_factor_confirmed_at' => 'datetime',
            'two_factor_enabled' => 'boolean',
        ];
    }

    /**
     * 🔒 NOUVEAU : Méthode sécurisée pour activer 2FA
     * Évite le mass assignment des champs 2FA
     */
    public function enableTwoFactor($secret, $recoveryCodes)
    {
        $this->two_factor_secret = encrypt($secret);
        $this->two_factor_recovery_codes = encrypt(json_encode($recoveryCodes));
        $this->two_factor_enabled = true;
        $this->two_factor_confirmed_at = now();
        $this->save();
        
        Log::info('2FA enabled securely', ['user_id' => $this->id]);
    }

    /**
     * 🔒 NOUVEAU : Méthode sécurisée pour désactiver 2FA
     */
    public function disableTwoFactor()
    {
        $this->two_factor_secret = null;
        $this->two_factor_recovery_codes = null;
        $this->two_factor_enabled = false;
        $this->two_factor_confirmed_at = null;
        $this->save();
        
        Log::info('2FA disabled securely', ['user_id' => $this->id]);
    }

    /**
     * 🔒 VALIDATION : Création d'utilisateur sécurisée uniquement
     */
    public static function createSecurely($validatedData)
    {
        // Seuls les champs autorisés
        $allowedFields = ['name', 'email', 'password'];
        $secureData = array_intersect_key($validatedData, array_flip($allowedFields));
        
        return self::create($secureData);
    }

    // ... reste des méthodes identiques ...
    
    public function hasTwoFactorEnabled(): bool
    {
        Log::info('Checking 2FA status for user ' . $this->email, [
            'two_factor_enabled' => $this->two_factor_enabled,
            'has_secret' => !empty($this->two_factor_secret),
            'confirmed_at' => $this->two_factor_confirmed_at,
        ]);

        return $this->two_factor_enabled && 
               !empty($this->two_factor_secret) && 
               !is_null($this->two_factor_confirmed_at);
    }

    public function hasRecoveryCodes(): bool
    {
        return !empty($this->two_factor_recovery_codes);
    }

    public function getRecoveryCodesCount(): int
    {
        if (empty($this->two_factor_recovery_codes)) {
            return 0;
        }

        try {
            $codes = json_decode(decrypt($this->two_factor_recovery_codes), true);
            return is_array($codes) ? count($codes) : 0;
        } catch (\Exception $e) {
            Log::error('Error counting recovery codes: ' . $e->getMessage());
            return 0;
        }
    }

    public function toApiArray(): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'email' => $this->email,
            'two_factor_enabled' => $this->two_factor_enabled,
            'two_factor_confirmed_at' => $this->two_factor_confirmed_at,
            'has_recovery_codes' => $this->hasRecoveryCodes(),
            'recovery_codes_count' => $this->getRecoveryCodesCount(),
            'created_at' => $this->created_at,
            'updated_at' => $this->updated_at,
        ];
    }
}