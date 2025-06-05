<?php

return [
    /*
    |--------------------------------------------------------------------------
    | JWT Authentication Secret
    |--------------------------------------------------------------------------
    */
    'secret' => env('JWT_SECRET'),

    /*
    |--------------------------------------------------------------------------
    | JWT time to live
    |--------------------------------------------------------------------------
    | Specify the length of time (in seconds) that the token will be valid for.
    | Defaults to 1 hour.
    */
    'ttl' => env('JWT_TTL', 3600),

    /*
    |--------------------------------------------------------------------------
    | Refresh time to live
    |--------------------------------------------------------------------------
    | Specify the length of time (in seconds) that the token can be refreshed
    | within. I.E. The user can refresh their token within a 2 week window.
    */
    'refresh_ttl' => env('JWT_REFRESH_TTL', 604800),

    /*
    |--------------------------------------------------------------------------
    | JWT hashing algorithm
    |--------------------------------------------------------------------------
    */
    'algo' => env('JWT_ALGO', 'HS256'),

    /*
    |--------------------------------------------------------------------------
    | Required Claims
    |--------------------------------------------------------------------------
    */
    'required_claims' => [
        'iss', // Issuer (qui a émis le token)
        'iat', // Issued at (quand)
        'exp', // Expiration
        'nbf', // Not before
        'sub', // Subject (user_id)
        'jti', // JWT ID (identifiant unique)
    ],

    /*
    |--------------------------------------------------------------------------
    | Persistent Claims
    |--------------------------------------------------------------------------
    | Claims qui seront toujours inclus dans vos tokens
    */
    'persistent_claims' => [
        // Ajoutez ici les claims spécifiques à 3713
    ],

    /*
    |--------------------------------------------------------------------------
    | Blacklist Enabled
    |--------------------------------------------------------------------------
    | Pour pouvoir révoquer des tokens (logout)
    */
    'blacklist_enabled' => env('JWT_BLACKLIST_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Providers
    |--------------------------------------------------------------------------
    */
    'providers' => [
        'jwt' => 'App\Services\JWTService',
        'auth' => 'App\Services\JWTAuthService',
        'storage' => 'App\Services\JWTStorageService',
    ],
];