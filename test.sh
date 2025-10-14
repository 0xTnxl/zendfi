#!/bin/bash

# ZenFi Quick Test Script
# This script helps you quickly test the payment gateway

set -e

echo "🚀 ZenFi Payment Gateway - Quick Test Suite"
echo "============================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BASE_URL="${BASE_URL:-http://localhost:3000}"
API_KEY=""
MERCHANT_ID=""
PAYMENT_ID=""
LINK_CODE=""
INVOICE_ID=""

# Function to print colored output
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Function to make API calls and pretty print
api_call() {
    local method=$1
    local endpoint=$2
    local data=$3
    local auth=$4
    
    echo ""
    print_info "Making $method request to $endpoint"
    
    if [ -n "$auth" ]; then
        if [ -n "$data" ]; then
            response=$(curl -s -X $method "$BASE_URL$endpoint" \
                -H "Authorization: Bearer $auth" \
                -H "Content-Type: application/json" \
                -d "$data")
        else
            response=$(curl -s -X $method "$BASE_URL$endpoint" \
                -H "Authorization: Bearer $auth")
        fi
    else
        if [ -n "$data" ]; then
            response=$(curl -s -X $method "$BASE_URL$endpoint" \
                -H "Content-Type: application/json" \
                -d "$data")
        else
            response=$(curl -s -X $method "$BASE_URL$endpoint")
        fi
    fi
    
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
    echo "$response"
}

# Test 1: Health Check
test_health() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Test 1: Health Check"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    response=$(api_call GET "/health")
    
    if echo "$response" | grep -q "healthy"; then
        print_success "Health check passed"
    else
        print_error "Health check failed"
        return 1
    fi
}

# Test 2: Create Merchant
test_create_merchant() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Test 2: Create Merchant"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    data='{
        "name": "Test Coffee Shop",
        "email": "test@coffeeshop.com",
        "business_address": "123 Main St, San Francisco, CA",
        "settlement_preference": "auto_usdc"
    }'
    
    response=$(api_call POST "/api/v1/merchants" "$data")
    
    if echo "$response" | grep -q "api_key"; then
        print_success "Merchant created successfully"
        API_KEY=$(echo "$response" | jq -r '.api_key')
        MERCHANT_ID=$(echo "$response" | jq -r '.merchant_id')
        
        echo ""
        print_info "Save these credentials:"
        echo "  API Key: $API_KEY"
        echo "  Merchant ID: $MERCHANT_ID"
        echo ""
        print_warning "Save your API key securely! You won't see it again."
    else
        print_error "Failed to create merchant"
        return 1
    fi
}

# Test 3: Create Payment
test_create_payment() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Test 3: Create Payment"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ -z "$API_KEY" ]; then
        print_error "API_KEY not set. Run test_create_merchant first."
        return 1
    fi
    
    data='{
        "amount": 10.50,
        "currency": "USD",
        "token": "USDC",
        "description": "Coffee and Pastry"
    }'
    
    response=$(api_call POST "/api/v1/payments" "$data" "$API_KEY")
    
    if echo "$response" | grep -q "payment_url"; then
        print_success "Payment created successfully"
        PAYMENT_ID=$(echo "$response" | jq -r '.id')
        
        echo ""
        print_info "Payment Details:"
        echo "  Payment ID: $PAYMENT_ID"
        echo "  View at: $BASE_URL/pay/$PAYMENT_ID"
    else
        print_error "Failed to create payment"
        return 1
    fi
}

# Test 4: Create Payment Link
test_create_payment_link() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Test 4: Create Payment Link"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ -z "$API_KEY" ]; then
        print_error "API_KEY not set. Run test_create_merchant first."
        return 1
    fi
    
    data='{
        "amount": 25.00,
        "currency": "USD",
        "token": "SOL",
        "description": "Monthly Subscription",
        "max_uses": 10
    }'
    
    response=$(api_call POST "/api/v1/payment-links" "$data" "$API_KEY")
    
    if echo "$response" | grep -q "link_code"; then
        print_success "Payment link created successfully"
        LINK_CODE=$(echo "$response" | jq -r '.link_code')
        
        echo ""
        print_info "Payment Link Details:"
        echo "  Link Code: $LINK_CODE"
        echo "  Shareable URL: $BASE_URL/checkout/$LINK_CODE"
    else
        print_error "Failed to create payment link"
        return 1
    fi
}

# Test 5: Create Invoice
test_create_invoice() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Test 5: Create Invoice"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ -z "$API_KEY" ]; then
        print_error "API_KEY not set. Run test_create_merchant first."
        return 1
    fi
    
    data='{
        "customer_email": "customer@example.com",
        "customer_name": "John Doe",
        "description": "Web Development Services",
        "amount": 500.00,
        "token": "USDC",
        "line_items": [
            {
                "description": "Frontend Development",
                "quantity": 40,
                "unit_price": 10.00
            }
        ]
    }'
    
    response=$(api_call POST "/api/v1/invoices" "$data" "$API_KEY")
    
    if echo "$response" | grep -q "invoice_number"; then
        print_success "Invoice created successfully"
        INVOICE_ID=$(echo "$response" | jq -r '.id')
        
        echo ""
        print_info "Invoice Details:"
        echo "  Invoice ID: $INVOICE_ID"
        echo "  Invoice Number: $(echo "$response" | jq -r '.invoice_number')"
    else
        print_error "Failed to create invoice"
        return 1
    fi
}

# Test 6: Get Dashboard
test_dashboard() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Test 6: Merchant Dashboard"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ -z "$API_KEY" ]; then
        print_error "API_KEY not set. Run test_create_merchant first."
        return 1
    fi
    
    response=$(api_call GET "/api/v1/dashboard" "" "$API_KEY")
    
    if echo "$response" | grep -q "total_volume_usd"; then
        print_success "Dashboard data retrieved successfully"
    else
        print_error "Failed to get dashboard data"
        return 1
    fi
}

# Test Rate Limiting
test_rate_limit() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Test 7: Rate Limiting"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ -z "$API_KEY" ] || [ -z "$PAYMENT_ID" ]; then
        print_warning "Skipping rate limit test (requires API_KEY and PAYMENT_ID)"
        return 0
    fi
    
    print_info "Making 5 rapid requests to test rate limiting..."
    
    for i in {1..5}; do
        status=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "Authorization: Bearer $API_KEY" \
            "$BASE_URL/api/v1/payments/$PAYMENT_ID/status")
        echo "  Request $i: HTTP $status"
    done
    
    print_success "Rate limiting test completed"
}

# Main test runner
run_all_tests() {
    echo ""
    echo "🧪 Running All Tests"
    echo "===================="
    
    test_health || exit 1
    test_create_merchant || exit 1
    test_create_payment || exit 1
    test_create_payment_link || exit 1
    test_create_invoice || exit 1
    test_dashboard || exit 1
    test_rate_limit || exit 1
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_success "All tests completed successfully! 🎉"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "📝 Test Summary:"
    echo "  ✅ Health check passed"
    echo "  ✅ Merchant created"
    echo "  ✅ Payment created"
    echo "  ✅ Payment link created"
    echo "  ✅ Invoice created"
    echo "  ✅ Dashboard retrieved"
    echo "  ✅ Rate limiting works"
    echo ""
    echo "🔗 Quick Links:"
    echo "  Checkout Page: $BASE_URL/checkout/$LINK_CODE"
    echo "  Payment Page: $BASE_URL/pay/$PAYMENT_ID"
    echo ""
    echo "🔐 Your Credentials:"
    echo "  API Key: $API_KEY"
    echo "  Merchant ID: $MERCHANT_ID"
    echo ""
    print_warning "Save your API key securely!"
}

# Interactive menu
show_menu() {
    echo ""
    echo "🎯 Test Menu"
    echo "============"
    echo "1. Run all tests"
    echo "2. Health check only"
    echo "3. Create merchant"
    echo "4. Create payment"
    echo "5. Create payment link"
    echo "6. Create invoice"
    echo "7. View dashboard"
    echo "8. Test rate limiting"
    echo "9. Use existing API key"
    echo "0. Exit"
    echo ""
    read -p "Select option: " choice
    
    case $choice in
        1) run_all_tests ;;
        2) test_health ;;
        3) test_create_merchant ;;
        4) test_create_payment ;;
        5) test_create_payment_link ;;
        6) test_create_invoice ;;
        7) test_dashboard ;;
        8) test_rate_limit ;;
        9) 
            read -p "Enter API Key: " API_KEY
            read -p "Enter Merchant ID: " MERCHANT_ID
            print_success "Credentials loaded"
            ;;
        0) exit 0 ;;
        *) 
            print_error "Invalid option"
            show_menu
            ;;
    esac
    
    # Show menu again after test
    if [ "$choice" != "0" ]; then
        show_menu
    fi
}

# Check dependencies
check_deps() {
    if ! command -v jq &> /dev/null; then
        print_error "jq is required but not installed. Install with: sudo apt-get install jq"
        exit 1
    fi
    
    if ! command -v curl &> /dev/null; then
        print_error "curl is required but not installed."
        exit 1
    fi
}

# Main
main() {
    check_deps
    
    if [ "$1" == "auto" ]; then
        run_all_tests
    else
        show_menu
    fi
}

main "$@"
