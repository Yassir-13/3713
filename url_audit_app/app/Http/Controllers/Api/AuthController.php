<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    /**
     * Handle user registration.
     */
    public function register(Request $request)
    {
        // Validation des données d'entrée
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',  // La confirmation du mot de passe est requise
        ]);
    
        // Si la validation échoue, retourner une erreur de validation avec les détails
        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()  // Retourner les erreurs détaillées
            ], 422);  // Code de statut 422 pour les erreurs de validation
        }
    
        try {
            // Création du nouvel utilisateur dans la base de données
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),  // Hachage du mot de passe
            ]);
    
            // Générer un token pour l'utilisateur nouvellement créé
            $token = $user->createToken('auth_token')->plainTextToken;
    
            return response()->json([
                'message' => 'User registered successfully',
                'user' => $user,
                'token' => $token,  // Retourne le token
            ]);
        } catch (\Exception $e) {
            // Gestion des erreurs lors de la création de l'utilisateur
            return response()->json([
                'message' => 'An error occurred while creating the user.',
                'error' => $e->getMessage(),
            ], 500);
        }
    }public function login(Request $request)
    {
        // Validation des données d'entrée
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);
    
        // Recherche de l'utilisateur avec l'email
        $user = User::where('email', $request->email)->first();
    
        // Vérification si l'utilisateur existe et si le mot de passe est correct
        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'message' => 'Invalid credentials',  // Message d'erreur si l'email ou mot de passe est incorrect
            ], 401);  // Code d'erreur 401 (Non autorisé)
        }
    
        // Générer un token pour l'utilisateur
        $token = $user->createToken('YourAppName')->plainTextToken;

    
        return response()->json([
            'message' => 'Successfully logged in',
              'user' => $user,  // Retourner l'utilisateur pour validation côté frontend
            'token' => $token,  // Retour du token pour la connexion
        ]);
    }
    
public function logout(Request $request)
{
    // Supprimer le token actuel pour déconnecter l'utilisateur
    $request->user()->currentAccessToken()->delete();

    return response()->json(['message' => 'Logged out successfully']);
}

    
}
