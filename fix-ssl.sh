#!/bin/bash

# KeyPouch SSL Setup Fix
# This script fixes WebSocket and development issues with SSL setup

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

# Check if containers are running
check_containers() {
    log "Checking container status..."
    if ! docker compose ps | grep -q "Up"; then
        error "Containers are not running. Please start with: docker compose -f docker-compose.yml -f docker-compose.ssl.yml up -d"
        exit 1
    fi
}

# Fix WebSocket issues by updating Vite configuration
fix_vite_config() {
    log "Updating Vite configuration for SSL proxy setup..."
    
    # Create a production-ready configuration
    cat > /home/shree/Keypouch/web/vite.config.ts << 'EOF'
import path from 'path';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
    const env = loadEnv(mode, '.', '');
    return {
      server: {
        port: 3000,
        host: '0.0.0.0',
        // Configure for proxy setup
        hmr: {
          port: 3000,
        },
        // Configure client to work behind proxy
        cors: true,
        // Disable strict port checking for development
        strictPort: false,
      },
      plugins: [react()],
      css: {
        postcss: './postcss.config.cjs',
      },
      define: {
        'process.env.API_KEY': JSON.stringify(env.GEMINI_API_KEY),
        'process.env.GEMINI_API_KEY': JSON.stringify(env.GEMINI_API_KEY)
      },
      resolve: {
        alias: {
          '@': path.resolve(__dirname, '.'),
        }
      }
    };
});
EOF
    
    log "Vite configuration updated"
}

# Update environment variables for SSL
update_env() {
    log "Updating environment variables for SSL..."
    
    # Update .env file with proper SSL configuration
    sed -i 's|WSS_SOCKET_PORT=.*|WSS_SOCKET_PORT=443|' /home/shree/Keypouch/.env
    sed -i 's|WSS_SOCKET_PATH=.*|WSS_SOCKET_PATH=/|' /home/shree/Keypouch/.env
    
    log "Environment variables updated"
}

# Restart containers to apply changes
restart_containers() {
    log "Restarting containers to apply changes..."
    docker compose restart web
    docker restart keypouch-nginx-1
    log "Containers restarted"
}

# Verify SSL setup
verify_ssl() {
    log "Verifying SSL setup..."
    
    # Check if HTTPS is working
    if curl -k -s https://localhost/health | grep -q "healthy"; then
        log "✓ HTTPS is working correctly"
    else
        warning "⚠ HTTPS health check failed"
    fi
    
    # Check if API is accessible
    if curl -k -s https://localhost/api/demo/exists >/dev/null; then
        log "✓ API is accessible via HTTPS"
    else
        warning "⚠ API health check failed"
    fi
}

# Show browser instructions
show_browser_instructions() {
    echo ""
    log "Browser Setup Instructions:"
    echo "1. Clear your browser cache and cookies"
    echo "2. Navigate to: https://localhost"
    echo "3. Accept the self-signed certificate warning"
    echo "4. Try login with: admin / admin"
    echo ""
    log "To permanently trust the certificate:"
    echo "- Chrome: Settings → Privacy → Manage certificates → Import → ssl/keypouch.crt"
    echo "- Firefox: Settings → Privacy → Certificates → Import → ssl/keypouch.crt"
    echo ""
}

# Main execution
main() {
    log "Fixing KeyPouch SSL setup issues..."
    
    check_containers
    fix_vite_config
    update_env
    restart_containers
    verify_ssl
    show_browser_instructions
    
    log "SSL fix completed!"
    warning "Note: WebSocket HMR may not work perfectly behind SSL proxy in development"
    warning "For production, use: npm run build and serve static files"
}

# Run main function
main "$@"
