#!/bin/bash
# filepath: /home/tnxl/zendfi/reset_database_fixed.sh

set -e

echo "🗄️  ZendFi Database Reset Script (Fixed)"
echo "========================================"

DB_NAME="zendfi"
DB_USER="zendfi_user"
DB_PASSWORD="password"
DATABASE_URL="postgresql://${DB_USER}:${DB_PASSWORD}@localhost:5432/${DB_NAME}"

read -p "Are you sure you want to continue? (y/N): " confirm
if [[ $confirm != "y" && $confirm != "Y" ]]; then
    echo "❌ Aborted by user"
    exit 1
fi

echo "🔥 Starting database reset..."

# Drop and recreate with proper permissions
echo "📝 Step 1: Dropping and recreating database..."
sudo -u postgres psql -c "DROP DATABASE IF EXISTS ${DB_NAME};"
sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME};"
sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';" 2>/dev/null || echo "ℹ️  User exists"

# FIX: Grant proper permissions for PostgreSQL 15+
echo "🔧 Step 2: Setting up permissions..."
sudo -u postgres psql -d ${DB_NAME} -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};"
sudo -u postgres psql -d ${DB_NAME} -c "GRANT ALL ON SCHEMA public TO ${DB_USER};"
sudo -u postgres psql -d ${DB_NAME} -c "GRANT CREATE ON SCHEMA public TO ${DB_USER};"
sudo -u postgres psql -d ${DB_NAME} -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO ${DB_USER};"
sudo -u postgres psql -d ${DB_NAME} -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO ${DB_USER};"

echo "✅ Database and permissions set up successfully"

# Run migrations
echo "📝 Step 3: Running migrations..."
sqlx migrate run --database-url "${DATABASE_URL}" || {
    echo "❌ Failed to run migrations"
    exit 1
}

echo "✅ All migrations applied successfully"

# Test
echo "📝 Step 4: Testing..."
cargo build --quiet

echo ""
echo "🎉 Database Reset Complete!"
echo "🚀 Ready to run: cargo run"