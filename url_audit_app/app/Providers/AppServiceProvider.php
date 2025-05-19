<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Route;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register(): void
    {
        // Vous pouvez enregistrer des services ici
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot(): void
    {
        // Charger les routes de l'API
        Route::prefix('api')  // Définir un préfixe pour les routes API
            ->middleware('api') // Assigner le middleware API
            ->group(base_path('routes/api.php'));  // Charger le fichier api.php pour les routes
    }
}
