#!/bin/bash

# 🧪 Script de test JWT pour 3713
# ================================

# Configuration
BASE_URL="http://localhost:8000/api"
TEMP_FILE="/tmp/3713_jwt_test.tmp"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction d'affichage
print_step() {
    echo -e "\n${BLUE}==== $1 ====${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Vérifier que Laravel fonctionne
print_step "0. Vérification du serveur Laravel"
SERVER_CHECK=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/../up")
if [ "$SERVER_CHECK" = "200" ]; then
    print_success "Serveur Laravel en ligne"
else
    print_error "Serveur Laravel hors ligne. Lancer: php artisan serve"
    exit 1
fi

# Variables globales pour les tokens
ACCESS_TOKEN=""
REFRESH_TOKEN=""
USER_ID=""

print_step "1. Test d'inscription utilisateur"
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/register" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{
    "name": "Test User 3713",
    "email": "test@3713.com",
    "password": "password123",
    "password_confirmation": "password123"
  }')

echo "Response: $REGISTER_RESPONSE"

# Vérifier si l'inscription a réussi
if echo "$REGISTER_RESPONSE" | grep -q "access_token"; then
    print_success "Inscription réussie avec JWT"
    # Extraire les tokens de l'inscription
    ACCESS_TOKEN=$(echo "$REGISTER_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
    REFRESH_TOKEN=$(echo "$REGISTER_RESPONSE" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
    USER_ID=$(echo "$REGISTER_RESPONSE" | grep -o '"id":[^,]*' | head -1 | cut -d':' -f2)
    echo "Access Token: ${ACCESS_TOKEN:0:50}..."
    echo "Refresh Token: ${REFRESH_TOKEN:0:50}..."
else
    print_warning "Inscription échouée ou utilisateur existe déjà, test de login..."
fi

print_step "2. Test de connexion utilisateur"
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{
    "email": "test@3713.com",
    "password": "password123"
  }')

echo "Response: $LOGIN_RESPONSE"

# Vérifier si le login a réussi et extraire les tokens
if echo "$LOGIN_RESPONSE" | grep -q "access_token"; then
    print_success "Connexion réussie avec JWT"
    ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
    REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
    USER_ID=$(echo "$LOGIN_RESPONSE" | grep -o '"id":[^,]*' | head -1 | cut -d':' -f2)
    echo "Access Token: ${ACCESS_TOKEN:0:50}..."
    echo "Refresh Token: ${REFRESH_TOKEN:0:50}..."
elif echo "$LOGIN_RESPONSE" | grep -q "requires_2fa"; then
    print_warning "2FA requis pour cet utilisateur"
    # Extraire le token temporaire
    TEMP_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"temp_token":"[^"]*"' | cut -d'"' -f4)
    echo "Token temporaire: ${TEMP_TOKEN:0:50}..."
    print_warning "Entrez le code 2FA manuellement pour continuer"
else
    print_error "Connexion échouée"
    echo "$LOGIN_RESPONSE"
    exit 1
fi

# Si on a un token, continuer les tests
if [ -n "$ACCESS_TOKEN" ]; then
    
    print_step "3. Test de validation du token (/auth/me)"
    ME_RESPONSE=$(curl -s -X GET "$BASE_URL/auth/me" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Accept: application/json")
    
    echo "Response: $ME_RESPONSE"
    
    if echo "$ME_RESPONSE" | grep -q "user"; then
        print_success "Token validé avec succès"
    else
        print_error "Token invalide"
        echo "$ME_RESPONSE"
    fi
    
    print_step "4. Test de scan avec JWT"
    SCAN_RESPONSE=$(curl -s -X POST "$BASE_URL/scan" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json" \
      -d '{"url": "https://httpbin.org"}')
    
    echo "Response: $SCAN_RESPONSE"
    
    if echo "$SCAN_RESPONSE" | grep -q "scan_id"; then
        print_success "Scan lancé avec succès"
        SCAN_ID=$(echo "$SCAN_RESPONSE" | grep -o '"scan_id":"[^"]*"' | cut -d'"' -f4)
        echo "Scan ID: $SCAN_ID"
        
        # Test de récupération des résultats
        print_step "5. Test de récupération des résultats"
        sleep 2  # Attendre un peu
        RESULTS_RESPONSE=$(curl -s -X GET "$BASE_URL/scan-results/$SCAN_ID" \
          -H "Authorization: Bearer $ACCESS_TOKEN" \
          -H "Accept: application/json")
        
        echo "Response: $RESULTS_RESPONSE"
        
        if echo "$RESULTS_RESPONSE" | grep -q "status"; then
            print_success "Résultats récupérés"
        else
            print_error "Erreur récupération résultats"
        fi
    else
        print_error "Échec lancement du scan"
        echo "$SCAN_RESPONSE"
    fi
    
    print_step "6. Test de l'historique des scans"
    HISTORY_RESPONSE=$(curl -s -X GET "$BASE_URL/user-scans" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Accept: application/json")
    
    echo "Response: $HISTORY_RESPONSE"
    
    if echo "$HISTORY_RESPONSE" | grep -q "\["; then
        print_success "Historique récupéré"
    else
        print_error "Erreur récupération historique"
    fi
    
    # Test du refresh token si disponible
    if [ -n "$REFRESH_TOKEN" ]; then
        print_step "7. Test de refresh token"
        REFRESH_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/refresh" \
          -H "Content-Type: application/json" \
          -H "Accept: application/json" \
          -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}")
        
        echo "Response: $REFRESH_RESPONSE"
        
        if echo "$REFRESH_RESPONSE" | grep -q "access_token"; then
            print_success "Token rafraîchi avec succès"
            NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
            echo "Nouveau token: ${NEW_ACCESS_TOKEN:0:50}..."
        else
            print_error "Échec du refresh"
        fi
    fi
    
    print_step "8. Test de logout"
    LOGOUT_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/logout" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Accept: application/json")
    
    echo "Response: $LOGOUT_RESPONSE"
    
    if echo "$LOGOUT_RESPONSE" | grep -q "successfully"; then
        print_success "Logout réussi"
    else
        print_error "Échec du logout"
    fi
    
    print_step "9. Test d'accès après logout (doit échouer)"
    AFTER_LOGOUT_RESPONSE=$(curl -s -X GET "$BASE_URL/auth/me" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Accept: application/json")
    
    echo "Response: $AFTER_LOGOUT_RESPONSE"
    
    if echo "$AFTER_LOGOUT_RESPONSE" | grep -q "Token invalide\|Unauthenticated"; then
        print_success "Token correctement révoqué"
    else
        print_error "Token toujours valide après logout!"
    fi

fi

print_step "RÉSUMÉ DES TESTS"
echo -e "${GREEN}✅ Tests JWT 3713 terminés!${NC}"
echo -e "${YELLOW}📋 Vérifiez les résultats ci-dessus${NC}"
echo -e "${BLUE}🔍 En cas d'erreur, vérifiez :${NC}"
echo "   - Le serveur Laravel (php artisan serve)"
echo "   - La configuration JWT dans .env"
echo "   - Les permissions de base de données"
echo "   - Les logs Laravel (storage/logs/laravel.log)"