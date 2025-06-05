<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

class GenerateJWTSecret extends Command
{
    protected $signature = 'jwt:secret';
    protected $description = 'Generate a secure JWT secret for 3713';

    public function handle()
    {
        $secret = base64_encode(random_bytes(64));
        
        $this->info('🔑 JWT Secret generated:');
        $this->line('');
        $this->line("JWT_SECRET={$secret}");
        $this->line('');
        $this->warn('⚠️  Copy this to your .env file and keep it secure!');
        $this->warn('⚠️  Never commit this secret to version control!');
        
        return 0;
    }
}