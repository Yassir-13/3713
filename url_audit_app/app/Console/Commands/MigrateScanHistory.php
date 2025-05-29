<?php
// app/Console/Commands/MigrateScanHistory.php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\ScanResult;
use App\Models\ScanHistory;

class MigrateScanHistory extends Command
{
    protected $signature = 'scan:migrate-history';
    protected $description = 'Migrate existing scan results to scan history';

    public function handle()
    {
        $this->info('Starting migration of existing scans to history...');
        
        $scans = ScanResult::all();
        $bar = $this->output->createProgressBar($scans->count());
        
        foreach ($scans as $scan) {
            // Vérifier si l'entrée historique existe déjà
            $exists = ScanHistory::where('scan_id', $scan->scan_id)->exists();
            
            if (!$exists) {
                ScanHistory::create([
                    'scan_id' => $scan->scan_id,
                    'user_id' => $scan->user_id,
                    'url' => $scan->url,
                    'status' => $scan->status,
                    'created_at' => $scan->created_at,
                    'updated_at' => $scan->updated_at
                ]);
            }
            
            $bar->advance();
        }
        
        $bar->finish();
        $this->newLine();
        $this->info('Migration completed successfully!');
    }
}