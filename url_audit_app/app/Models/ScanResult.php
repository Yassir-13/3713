<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ScanResult extends Model
{
    use HasFactory;
    
    protected $fillable = [
        'scan_id',
        'url',
        'status',
        'user_id',
        'whatweb_output',
        'sslyze_output',
        'zap_output',
        'nuclei_output',
        'error',
        'gemini_analysis'  // Ajoutez ce champ
    ];

    /**
     * Relation avec l'utilisateur propriétaire du scan
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }
    
    public function history()
    {
        return $this->hasOne(ScanHistory::class, 'scan_id', 'scan_id');
    }

    /**
     * Récupère le dernier scan complet pour une URL donnée
     */
    public static function getLastCompleteForUrl($url)
    {
        return self::where('url', $url)
                  ->where('status', 'completed')
                  ->latest()
                  ->first();
    }
}