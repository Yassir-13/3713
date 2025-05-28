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
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
        'two_factor_secret',
        'two_factor_recovery_codes',
        'two_factor_confirmed_at',
        'two_factor_enabled',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
        'two_factor_secret',
        'two_factor_recovery_codes',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
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
     * 🔗 RELATION avec ScanResult
     */
    public function scans()
    {
        return $this->hasMany(\App\Models\ScanResult::class);
    }

    // 🔐 MÉTHODES A2F - CRITIQUES POUR LE FONCTIONNEMENT

    /**
     * ⭐ MÉTHODE PRINCIPALE - Vérifier si l'utilisateur a l'A2F activé
     * Cette méthode est appelée par AuthController::login()
     */
    public function hasTwoFactorEnabled(): bool
    {
        // Debug pour voir ce qui se passe
        Log::info('🔍 Checking 2FA status for user ' . $this->email, [
            'two_factor_enabled' => $this->two_factor_enabled,
            'has_secret' => !empty($this->two_factor_secret),
            'confirmed_at' => $this->two_factor_confirmed_at,
        ]);

        return $this->two_factor_enabled && 
               !empty($this->two_factor_secret) && 
               !is_null($this->two_factor_confirmed_at);
    }

    /**
     * Vérifier si l'utilisateur a des codes de récupération
     */
    public function hasRecoveryCodes(): bool
    {
        return !empty($this->two_factor_recovery_codes);
    }

    /**
     * Obtenir le nombre de codes de récupération restants
     */
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

    /**
     * Formatage pour les réponses API (sans données sensibles)
     */
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

    /**
     * 🆕 MÉTHODE DEBUG - Pour diagnostiquer les problèmes A2F
     */
    public function debug2FAStatus(): array
    {
        return [
            'user_id' => $this->id,
            'email' => $this->email,
            'two_factor_enabled' => $this->two_factor_enabled,
            'has_two_factor_secret' => !empty($this->two_factor_secret),
            'two_factor_confirmed_at' => $this->two_factor_confirmed_at,
            'has_recovery_codes' => $this->hasRecoveryCodes(),
            'recovery_codes_count' => $this->getRecoveryCodesCount(),
            'hasTwoFactorEnabled_result' => $this->hasTwoFactorEnabled(),
        ];
    }
}