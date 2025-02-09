#!/bin/bash

# Create necessary directories if they don't exist
mkdir -p src/desktop_manager/{api/{routes,models,services},core,config,utils}

# Move route files
mv routes/auth_routes.py src/desktop_manager/api/routes/
mv routes/connection_routes.py src/desktop_manager/api/routes/
mv routes/user_routes.py src/desktop_manager/api/routes/

# Move core files
mv database.py src/desktop_manager/core/
mv auth.py src/desktop_manager/core/
mv guacamole.py src/desktop_manager/core/
mv rancher.py src/desktop_manager/core/
mv helm.py src/desktop_manager/core/

# Move config files
mv config.py src/desktop_manager/config/

# Move utility files
mv utils.py src/desktop_manager/utils/

# Clean up empty directories
rm -rf routes/

echo "Migration completed!" 