#!/bin/bash
# test-security.sh - Script de test sécurité 3713
# Usage: ./test-security.sh [base_url]

BASE_URL="${1:-http://localhost:8000}"
API_URL="${BASE_URL}/api"

echo "🔒 === TEST DE SÉCURITÉ 3713 ==="
echo "Base URL: $BASE_URL"
echo "=================================="

# Couleurs pour les résultats
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction pour tester et afficher le résultat
test_endpoint() {
    local test_name="$1"
    local expected_result="$2"
    shift 2
    local curl_cmd="$@"
    
    echo -e "\n${BLUE}🧪 Test: $test_name${NC}"
    echo "Commande: $curl_cmd"
    
    # Exécuter la commande et capturer le code de sortie
    response=$(eval "$curl_cmd" 2>/dev/null)
    http_code=$(eval "$curl_cmd -w '%{http_code}' -s -o /dev/null" 2>/dev/null)
    
    echo "Code HTTP: $http_code"
    
    if [[ "$expected_result" == "PASS" && "$http_code" == "200" ]]; then
        echo -e "${GREEN}✅ RÉUSSI${NC}"
        echo "Réponse: $(echo "$response" | head -c 200)..."
    elif [[ "$expected_result" == "FAIL" && ("$http_code" == "400" || "$http_code" == "403" || "$http_code" == "401") ]]; then
        echo -e "${GREEN}✅ BLOQUÉ (comme attendu)${NC}"
    elif [[ "$expected_result" == "FAIL" && "$http_code" == "200" ]]; then
        echo -e "${RED}❌ ÉCHOUÉ - Devrait être bloqué!${NC}"
        echo "Réponse: $(echo "$response" | head -c 200)..."
    else
        echo -e "${YELLOW}⚠️  INATTENDU (Code: $http_code)${NC}"
        echo "Réponse: $(echo "$response" | head -c 200)..."
    fi
}

echo -e "\n${BLUE}=== 1. TESTS CORS ===${NC}"

# Test 1: Origin autorisé
test_endpoint "Origin autorisé (localhost:5173)" "PASS" \
    "curl -H 'Origin: http://localhost:5173' -s '$API_URL/security-test'"

# Test 2: Origin malveillant (DOIT ÊTRE BLOQUÉ)
test_endpoint "Origin malveillant (DOIT ÉCHOUER)" "FAIL" \
    "curl -H 'Origin: http://malicious.com' -s '$API_URL/security-test'"

# Test 3: Preflight CORS
test_endpoint "Preflight CORS (OPTIONS)" "PASS" \
    "curl -H 'Origin: http://localhost:5173' \
          -H 'Access-Control-Request-Method: POST' \
          -H 'Access-Control-Request-Headers: Content-Type,Authorization' \
          -X OPTIONS -s '$API_URL/security-test'"

echo -e "\n${BLUE}=== 2. TESTS HEADERS PERSONNALISÉS ===${NC}"

# Test 4: Headers valides
test_endpoint "Headers valides" "PASS" \
    "curl -H 'Origin: http://localhost:5173' \
          -H 'X-API-Version: v1' \
          -H 'X-Client-ID: client_abc123def456' \
          -s '$API_URL/security-test'"

# Test 5: Client-ID invalide (en dev, peut passer avec warning)
test_endpoint "Client-ID invalide" "PASS" \
    "curl -H 'Origin: http://localhost:5173' \
          -H 'X-Client-ID: invalid' \
          -s '$API_URL/security-test'"

# Test 6: API Version invalide
test_endpoint "API Version invalide" "PASS" \
    "curl -H 'Origin: http://localhost:5173' \
          -H 'X-API-Version: v999' \
          -s '$API_URL/security-test'"

echo -e "\n${BLUE}=== 3. TESTS MIDDLEWARE STRICT ===${NC}"

# Test 7: Route stricte sans headers requis
test_endpoint "Route stricte sans headers (DOIT ÉCHOUER)" "FAIL" \
    "curl -H 'Origin: http://localhost:5173' \
          -s '$API_URL/security-test-strict'"

# Test 8: Route stricte avec headers requis
test_endpoint "Route stricte avec headers" "PASS" \
    "curl -H 'Origin: http://localhost:5173' \
          -H 'X-API-Version: v1' \
          -H 'X-Client-ID: 3713_abc123def456789a' \
          -s '$API_URL/security-test-strict'"

echo -e "\n${BLUE}=== 4. TESTS JWT (si disponible) ===${NC}"

# Créer un token de test valide (si possible)
JWT_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwiaXNzIjoiMzcxMyIsImF1ZCI6IjM3MTMtdXNlcnMiLCJpYXQiOjE2NzUxMDQwMDAsImV4cCI6OTk5OTk5OTk5OSwianRpIjoidGVzdF90b2tlbiIsInVzZXIiOnsiaWQiOjEsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsIm5hbWUiOiJUZXN0IFVzZXIifSwic2VjdXJpdHkiOnsic2Nhbl9wZXJtaXNzaW9ucyI6WyJiYXNpY19zY2FuIl19fQ.test"

# Test 9: JWT invalide
test_endpoint "JWT invalide (DOIT ÉCHOUER)" "FAIL" \
    "curl -H 'Origin: http://localhost:5173' \
          -H 'Authorization: Bearer invalid_token' \
          -s '$API_URL/jwt-test'"

# Test 10: Sans JWT sur route protégée
test_endpoint "Sans JWT sur route protégée (DOIT ÉCHOUER)" "FAIL" \
    "curl -H 'Origin: http://localhost:5173' \
          -s '$API_URL/jwt-test'"

echo -e "\n${BLUE}=== 5. TESTS DIVERS SÉCURITÉ ===${NC}"

# Test 11: Headers de sécurité dans la réponse
echo -e "\n${BLUE}🧪 Test: Headers de sécurité dans la réponse${NC}"
response_headers=$(curl -H 'Origin: http://localhost:5173' \
                       -I -s "$API_URL/security-test" | grep -E "X-|Content-Security-Policy|Strict-Transport")

if [[ -n "$response_headers" ]]; then
    echo -e "${GREEN}✅ Headers de sécurité présents:${NC}"
    echo "$response_headers"
else
    echo -e "${YELLOW}⚠️  Aucun header de sécurité détecté${NC}"
fi

# Test 12: Rate limiting (si activé)
echo -e "\n${BLUE}🧪 Test: Rate limiting${NC}"
for i in {1..3}; do
    http_code=$(curl -H 'Origin: http://localhost:5173' \
                     -w '%{http_code}' -s -o /dev/null \
                     "$API_URL/security-test")
    echo "Requête $i: HTTP $http_code"
done

echo -e "\n${BLUE}=== RÉSUMÉ DES RECOMMANDATIONS ===${NC}"
echo "1. ✅ Si les tests CORS malveillants PASSENT → Problème CORS critique"
echo "2. ✅ Si les headers invalides PASSENT en production → Durcir la validation"
echo "3. ✅ Si les routes strictes PASSENT sans headers → Problème middleware"
echo "4. ✅ Si aucun header de sécurité → Ajouter SecurityHeaders middleware"
echo "5. ✅ Vérifiez les logs Laravel pour les warnings de validation"

echo -e "\n${GREEN}=== TEST TERMINÉ ===${NC}"
echo "Vérifiez les logs Laravel: tail -f storage/logs/laravel.log"
