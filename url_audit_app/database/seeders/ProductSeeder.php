<?php

namespace Database\Seeders;

use App\Models\Product;
use Illuminate\Database\Seeder;

class ProductSeeder extends Seeder
{
    public function run()
    {
        Product::create([
            'name' => 'Produit test 1',
            'description' => 'Description du produit test 1',
            'price' => 19.99
        ]);
        
        Product::create([
            'name' => 'Produit test 2',
            'description' => 'Description du produit test 2',
            'price' => 29.99
        ]);
        
        Product::create([
            'name' => 'Produit test 3',
            'description' => 'Description du produit test 3',
            'price' => 39.99
        ]);
    }
}