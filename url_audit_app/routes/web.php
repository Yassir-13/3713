<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Response;


Route::get('/', function () {
    return view('welcome');
});

Route::get('/app', function () {
    $path = public_path('frontend/index.html');
    return File::get($path);
});
