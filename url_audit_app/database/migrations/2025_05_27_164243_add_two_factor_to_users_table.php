<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            // Secret A2F chiffré (généré par Google2FA)
            $table->string('two_factor_secret')->nullable()->after('password');
            
            // Codes de récupération d'urgence (8 codes chiffrés)
            $table->text('two_factor_recovery_codes')->nullable()->after('two_factor_secret');
            
            // Date/heure de confirmation de l'A2F
            $table->timestamp('two_factor_confirmed_at')->nullable()->after('two_factor_recovery_codes');
            
            // Statut A2F activé/désactivé
            $table->boolean('two_factor_enabled')->default(false)->after('two_factor_confirmed_at');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn([
                'two_factor_secret',
                'two_factor_recovery_codes', 
                'two_factor_confirmed_at',
                'two_factor_enabled'
            ]);
        });
    }
};