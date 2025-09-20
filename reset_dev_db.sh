# Quick reset script
# filepath: /home/tnxl/zendfi/scripts/reset_dev_db.sh

#!/bin/bash
echo "Resetting ZendFi development database..."

psql "postgresql://zendfi_user:password@localhost:5432/zendfi" << EOF
TRUNCATE TABLE webhook_events CASCADE;
TRUNCATE TABLE settlements CASCADE;
TRUNCATE TABLE api_keys CASCADE;
TRUNCATE TABLE payments CASCADE;
TRUNCATE TABLE merchants CASCADE;
TRUNCATE TABLE exchange_rates CASCADE;
EOF

echo "Database reset complete!"
echo "Run 'cargo run' to start fresh"