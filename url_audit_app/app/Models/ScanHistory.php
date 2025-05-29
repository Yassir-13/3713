<?php
// app/Models/ScanHistory.php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class ScanHistory extends Model
{
    use HasFactory;

    protected $table = 'scan_history';

    protected $fillable = [
        'scan_id',
        'user_id', 
        'url',
        'status',
        'is_favorite',
        'last_viewed_at',
        'user_notes'
    ];

    protected $casts = [
        'is_favorite' => 'boolean',
        'last_viewed_at' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime'
    ];

    // 🔗 RELATIONS
    
    /**
     * Relation avec l'utilisateur propriétaire
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Relation avec les détails complets du scan
     */
    public function scanResult()
    {
        return $this->belongsTo(ScanResult::class, 'scan_id', 'scan_id');
    }

    // 🎯 SCOPES UTILES
    
    /**
     * Scope pour les scans favoris
     */
    public function scopeFavorites($query)
    {
        return $query->where('is_favorite', true);
    }

    /**
     * Scope pour un utilisateur spécifique
     */
    public function scopeForUser($query, $userId)
    {
        return $query->where('user_id', $userId);
    }

    /**
     * Scope pour les scans terminés
     */
    public function scopeCompleted($query)
    {
        return $query->whereIn('status', ['completed', 'failed', 'timeout']);
    }

    // 🛠️ MÉTHODES UTILES
    
    /**
     * Marquer comme vu
     */
    public function markAsViewed()
    {
        $this->update(['last_viewed_at' => now()]);
    }

    /**
     * Basculer favori
     */
    public function toggleFavorite()
    {
        $this->update(['is_favorite' => !$this->is_favorite]);
        return $this->is_favorite;
    }
}