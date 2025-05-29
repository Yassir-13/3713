<?php
// database/migrations/xxxx_create_scan_history_table.php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('scan_history', function (Blueprint $table) {
            $table->id();
            
            // Données principales
            $table->string('scan_id', 36);
            $table->unsignedBigInteger('user_id');
            $table->string('url', 2048);
            $table->string('status', 20);
            
            // Métadonnées utilisateur
            $table->boolean('is_favorite')->default(false);
            $table->timestamp('last_viewed_at')->nullable();
            $table->text('user_notes')->nullable();
            
            // Timestamps
            $table->timestamps();
            
            //  CONTRAINTES DE CLÉ ÉTRANGÈRE
            $table->foreign('user_id')
                  ->references('id')
                  ->on('users')
                  ->onDelete('cascade');
                  
            $table->foreign('scan_id')
                  ->references('scan_id')
                  ->on('scan_results')
                  ->onDelete('cascade');
            
            // 📊 INDEX pour performance
            $table->index(['user_id', 'created_at'], 'idx_user_date');
            $table->index('scan_id', 'idx_scan_id');
            $table->index(['user_id', 'is_favorite'], 'idx_user_favorites');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('scan_history');
    }
};