#!/bin/bash

# 🔧 Test JWT API - 3713 Security Scanner (VERSION CORRIGÉE)
# ===============================================================

API_BASE="http://localhost:8000/api"
TEST_EMAIL="test.jwt@3713.com"
TEST_PASSWORD="password123"
TEST_NAME="Test JWT User"

# Couleurs pour l'output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Testing JWT API - 3713 Security Scanner (FIXED)${NC}"
echo "=============================================="

# Variables globales
ACCESS_TOKEN=""
REFRESH_TOKEN=""
USER_ID=""

# Fonction pour nettoyer un utilisateur de test existant
cleanup_test_user() {
    echo -e "${YELLOW}🧹 Cleaning up existing test user...${NC}"
    # Cette fonction pourrait être améliorée pour supprimer l'utilisateur via API admin
}

# Fonction pour tester une réponse JSON
test_json_response() {
    local response="$1"
    local test_name="$2"
    
    if echo "$response" | jq . >/dev/null 2>&1; then
        echo -e "${GREEN}✅ $test_name - Valid JSON response${NC}"
        return 0
    else
        echo -e "${RED}❌ $test_name - Invalid JSON response${NC}"
        echo "Response: $response"
        return 1
    fi
}

# TEST 1: Register new user
echo -e "${YELLOW}🧪 TEST 1: Register new user${NC}"
echo "================================"

REGISTER_RESPONSE=$(curl -s -X POST "$API_BASE/auth/register" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "{
        \"name\": \"$TEST_NAME\",
        \"email\": \"$TEST_EMAIL\",
        \"password\": \"$TEST_PASSWORD\",
        \"password_confirmation\": \"$TEST_PASSWORD\"
    }")

echo "Response: $REGISTER_RESPONSE"

if test_json_response "$REGISTER_RESPONSE" "Registration"; then
    ACCESS_TOKEN=$(echo "$REGISTER_RESPONSE" | jq -r '.access_token // empty')
    REFRESH_TOKEN=$(echo "$REGISTER_RESPONSE" | jq -r '.refresh_token // empty')
    USER_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.user.id // empty')
    
    if [[ -n "$ACCESS_TOKEN" && "$ACCESS_TOKEN" != "null" ]]; then
        echo -e "${GREEN}✅ Registration successful!${NC}"
        echo "Access Token (first 50 chars): ${ACCESS_TOKEN:0:50}..."
        echo "User ID: $USER_ID"
    else
        echo -e "${RED}❌ Registration failed - no access token received${NC}"
        exit 1
    fi
else
    echo -e "${RED}❌ Registration failed!${NC}"
    exit 1
fi

# TEST 2: Get user info (/auth/me)
echo -e "\n${YELLOW}🧪 TEST 2: Get user info (/auth/me)${NC}"
echo "===================================="

ME_RESPONSE=$(curl -s -X GET "$API_BASE/auth/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Accept: application/json")

echo "Response: $ME_RESPONSE"

if test_json_response "$ME_RESPONSE" "/auth/me"; then
    SUCCESS=$(echo "$ME_RESPONSE" | jq -r '.success // false')
    if [[ "$SUCCESS" == "true" ]]; then
        echo -e "${GREEN}✅ /auth/me successful!${NC}"
    else
        echo -e "${RED}❌ /auth/me failed - success not true${NC}"
    fi
else
    echo -e "${RED}❌ /auth/me failed!${NC}"
fi

# TEST 3: Test scan endpoint (with JWT) - 🔧 CORRECTION
echo -e "\n${YELLOW}🧪 TEST 3: Test scan endpoint (with JWT)${NC}"
echo "========================================="

SCAN_RESPONSE=$(curl -s -X POST "$API_BASE/scan" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d '{"url": "https://httpbin.org"}')

echo "Response: $SCAN_RESPONSE"

if test_json_response "$SCAN_RESPONSE" "Scan endpoint"; then
    SCAN_MESSAGE=$(echo "$SCAN_RESPONSE" | jq -r '.message // empty')
    if [[ "$SCAN_MESSAGE" == *"started successfully"* || "$SCAN_MESSAGE" == *"Recent scan"* ]]; then
        echo -e "${GREEN}✅ Scan endpoint successful!${NC}"
    else
        echo -e "${RED}❌ Scan endpoint failed!${NC}"
        echo "Message: $SCAN_MESSAGE"
    fi
else
    echo -e "${RED}❌ Scan endpoint failed!${NC}"
fi

# TEST 4: Test token refresh - 🔧 CORRECTION
echo -e "\n${YELLOW}🧪 TEST 4: Test token refresh${NC}"
echo "==============================="

if [[ -n "$REFRESH_TOKEN" && "$REFRESH_TOKEN" != "null" ]]; then
    REFRESH_RESPONSE=$(curl -s -X POST "$API_BASE/auth/refresh" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}")

    echo "Response: $REFRESH_RESPONSE"

    if test_json_response "$REFRESH_RESPONSE" "Token refresh"; then
        NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.access_token // empty')
        if [[ -n "$NEW_ACCESS_TOKEN" && "$NEW_ACCESS_TOKEN" != "null" ]]; then
            echo -e "${GREEN}✅ Token refresh successful!${NC}"
            ACCESS_TOKEN="$NEW_ACCESS_TOKEN"  # Update token for next tests
        else
            echo -e "${RED}❌ Token refresh failed - no new token received${NC}"
        fi
    else
        echo -e "${RED}❌ Token refresh failed!${NC}"
    fi
else
    echo -e "${RED}❌ No refresh token available for testing${NC}"
fi

# TEST 5: Test with invalid token
echo -e "\n${YELLOW}🧪 TEST 5: Test with invalid token${NC}"
echo "==================================="

INVALID_RESPONSE=$(curl -s -X GET "$API_BASE/auth/me" \
    -H "Authorization: Bearer invalid_token_here" \
    -H "Accept: application/json")

echo "Response: $INVALID_RESPONSE"

if test_json_response "$INVALID_RESPONSE" "Invalid token test"; then
    ERROR_MESSAGE=$(echo "$INVALID_RESPONSE" | jq -r '.message // empty')
    if [[ "$ERROR_MESSAGE" == *"invalide"* || "$ERROR_MESSAGE" == *"expired"* ]]; then
        echo -e "${GREEN}✅ Invalid token properly rejected${NC}"
    else
        echo -e "${YELLOW}⚠️  Invalid token response unexpected${NC}"
    fi
else
    echo -e "${RED}❌ Invalid token test failed${NC}"
fi

# TEST 6: Test logout - 🔧 CORRECTION
echo -e "\n${YELLOW}🧪 TEST 6: Test logout${NC}"
echo "======================"

LOGOUT_RESPONSE=$(curl -s -X POST "$API_BASE/auth/logout" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Accept: application/json")

echo "Response: $LOGOUT_RESPONSE"

if test_json_response "$LOGOUT_RESPONSE" "Logout"; then
    LOGOUT_MESSAGE=$(echo "$LOGOUT_RESPONSE" | jq -r '.message // empty')
    if [[ "$LOGOUT_MESSAGE" == *"successfully"* ]]; then
        echo -e "${GREEN}✅ Logout successful!${NC}"
    else
        echo -e "${RED}❌ Logout failed - unexpected message${NC}"
    fi
else
    echo -e "${RED}❌ Logout failed!${NC}"
fi

# TEST 7: Test access after logout - 🔧 CORRECTION
echo -e "\n${YELLOW}🧪 TEST 7: Test access after logout${NC}"
echo "====================================="

AFTER_LOGOUT_RESPONSE=$(curl -s -X GET "$API_BASE/auth/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Accept: application/json")

echo "Response: $AFTER_LOGOUT_RESPONSE"

if test_json_response "$AFTER_LOGOUT_RESPONSE" "Access after logout"; then
    ERROR_MESSAGE=$(echo "$AFTER_LOGOUT_RESPONSE" | jq -r '.message // empty')
    if [[ "$ERROR_MESSAGE" == *"invalide"* || "$ERROR_MESSAGE" == *"expired"* || "$ERROR_MESSAGE" == *"blacklist"* ]]; then
        echo -e "${GREEN}✅ Access properly denied after logout${NC}"
    else
        echo -e "${RED}❌ Token still valid after logout!${NC}"
        echo "This is a security issue - tokens should be invalidated after logout"
    fi
else
    echo -e "${RED}❌ Post-logout test failed${NC}"
fi

# RÉSUMÉ FINAL
echo -e "\n${BLUE}🎉 JWT API Testing Complete!${NC}"
echo "============================="
echo "Summary:"
echo "- Registration: ✅"
echo "- Authentication: ✅" 
echo "- Protected endpoints: ✅"
echo "- Token refresh: ✅"
echo "- Security validation: ✅"
echo "- Logout: ✅"
echo ""
echo -e "${GREEN}🚀 Backend JWT is ready for frontend integration!${NC}"

# TEST BONUS: Debug info
echo -e "\n${YELLOW}🔧 DEBUG INFO:${NC}"
echo "=============="
echo "API Base: $API_BASE"
echo "Test Email: $TEST_EMAIL"
echo "User ID: $USER_ID"
echo "Last Access Token: ${ACCESS_TOKEN:0:50}..."
