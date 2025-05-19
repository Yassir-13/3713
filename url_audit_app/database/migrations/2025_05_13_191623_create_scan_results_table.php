<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateScanResultsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('scan_results', function (Blueprint $table) {
            $table->id();
            $table->uuid('scan_id')->unique();
            $table->foreignId('user_id')->nullable()->constrained();
            $table->string('url');
            $table->string('status')->default('pending');
            $table->longText('whatweb_output')->nullable();
            $table->longText('sslyze_output')->nullable();
            $table->longText('zap_output')->nullable();
            $table->text('error')->nullable();
            $table->timestamps();
            
            // Ajouter un index pour optimiser les recherches
            $table->index('url');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('scan_results');
    }
}