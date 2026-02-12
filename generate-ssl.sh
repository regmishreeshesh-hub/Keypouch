#!/bin/bash

# KeyPouch Self-Signed SSL Certificate Generator
# This script creates self-signed certificates for HTTPS development

set -e

# Configuration
DOMAIN="localhost"
COUNTRY="US"
STATE="California"
CITY="San Francisco"
ORGANIZATION="KeyPouch"
ORGANIZATIONAL_UNIT="Development"
EMAIL="admin@keypouch.local"
CERT_DIR="./ssl"
VALIDITY_DAYS=365

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO:${NC} $1"
}

# Check if OpenSSL is available
check_openssl() {
    if ! command -v openssl &> /dev/null; then
        error "OpenSSL is not installed. Please install OpenSSL first."
        echo "Ubuntu/Debian: sudo apt-get install openssl"
        echo "CentOS/RHEL: sudo yum install openssl"
        echo "macOS: brew install openssl"
        exit 1
    fi
}

# Create SSL directory
create_cert_dir() {
    if [ ! -d "$CERT_DIR" ]; then
        log "Creating SSL certificate directory: $CERT_DIR"
        mkdir -p "$CERT_DIR"
    else
        log "SSL directory already exists: $CERT_DIR"
    fi
}

# Generate private key
generate_private_key() {
    log "Generating private key..."
    openssl genrsa -out "$CERT_DIR/keypouch.key" 2048
    log "Private key generated: $CERT_DIR/keypouch.key"
}

# Create certificate signing request
create_csr() {
    log "Creating certificate signing request..."
    openssl req -new -key "$CERT_DIR/keypouch.key" -out "$CERT_DIR/keypouch.csr" -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT/CN=$DOMAIN/emailAddress=$EMAIL"
    log "CSR created: $CERT_DIR/keypouch.csr"
}

# Generate self-signed certificate
generate_certificate() {
    log "Generating self-signed certificate (valid for $VALIDITY_DAYS days)..."
    openssl x509 -req -days $VALIDITY_DAYS -in "$CERT_DIR/keypouch.csr" -signkey "$CERT_DIR/keypouch.key" -out "$CERT_DIR/keypouch.crt" -extensions v3_req -extfile <(
        cat <<EOF
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
    )
    log "Certificate generated: $CERT_DIR/keypouch.crt"
}

# Generate DH parameters for better security
generate_dh_params() {
    log "Generating DH parameters (this may take a moment)..."
    openssl dhparam -out "$CERT_DIR/dhparam.pem" 2048
    log "DH parameters generated: $CERT_DIR/dhparam.pem"
}

# Set proper permissions
set_permissions() {
    log "Setting proper file permissions..."
    chmod 600 "$CERT_DIR/keypouch.key"
    chmod 644 "$CERT_DIR/keypouch.crt"
    chmod 644 "$CERT_DIR/dhparam.pem"
    chmod 600 "$CERT_DIR/keypouch.csr"
    log "Permissions set"
}

# Display certificate info
display_cert_info() {
    log "Certificate Information:"
    echo "----------------------------------------"
    openssl x509 -in "$CERT_DIR/keypouch.crt" -text -noout | grep -E "(Subject:|Issuer:|Not Before:|Not After:|DNS:|IP Address:)" -A 1
    echo "----------------------------------------"
    info "Certificate is valid for $VALIDITY_DAYS days"
    warning "This is a self-signed certificate. Browsers will show security warnings."
}

# Create Nginx configuration
create_nginx_config() {
    local nginx_config="$CERT_DIR/nginx.conf"
    log "Creating Nginx SSL configuration..."
    
    cat > "$nginx_config" << 'EOF'
# KeyPouch SSL Configuration for Nginx
# Place this in your nginx site configuration

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    
    server_name localhost;
    
    # SSL Certificate Configuration
    ssl_certificate /path/to/keypouch/ssl/keypouch.crt;
    ssl_certificate_key /path/to/keypouch/ssl/keypouch.key;
    
    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # DH Parameters
    ssl_dhparam /path/to/keypouch/ssl/dhparam.pem;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Your application proxy configuration
    location / {
        proxy_pass http://localhost:3002;  # KeyPouch web app
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
    
    # Backend API proxy
    location /api/ {
        proxy_pass http://localhost:5001;  # KeyPouch backend
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name localhost;
    return 301 https://$server_name$request_uri;
}
EOF
    
    log "Nginx configuration created: $nginx_config"
    info "Update the paths in the configuration to match your setup"
}

# Create Apache configuration
create_apache_config() {
    local apache_config="$CERT_DIR/apache.conf"
    log "Creating Apache SSL configuration..."
    
    cat > "$apache_config" << 'EOF'
# KeyPouch SSL Configuration for Apache
# Place this in your Apache site configuration

<VirtualHost *:443>
    ServerName localhost
    DocumentRoot /path/to/keypouch/web/build
    
    # SSL Configuration
    SSLEngine on
    SSLCertificateFile /path/to/keypouch/ssl/keypouch.crt
    SSLCertificateKeyFile /path/to/keypouch/ssl/keypouch.key
    SSLCertificateChainFile /path/to/keypouch/ssl/keypouch.crt
    
    # SSL Security Configuration
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384
    SSLHonorCipherOrder off
    SSLSessionCache shmcb:/var/run/apache2/ssl_scache(512000)
    SSLSessionCacheTimeout 300
    
    # Security Headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Frame-Options DENY
    Header always set X-Content-Type-Options nosniff
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Proxy Configuration for KeyPouch
    ProxyPreserveHost On
    ProxyRequests Off
    
    # Web application proxy
    ProxyPass / http://localhost:3002/
    ProxyPassReverse / http://localhost:3002/
    
    # API proxy
    ProxyPass /api/ http://localhost:5001/api/
    ProxyPassReverse /api/ http://localhost:5001/api/
</VirtualHost>

# Redirect HTTP to HTTPS
<VirtualHost *:80>
    ServerName localhost
    Redirect permanent / https://localhost/
</VirtualHost>
EOF
    
    log "Apache configuration created: $apache_config"
    info "Update the paths in the configuration to match your setup"
}

# Create Docker Compose override
create_docker_override() {
    local docker_override="$CERT_DIR/docker-compose.override.yml"
    log "Creating Docker Compose override for HTTPS..."
    
    cat > "$docker_override" << 'EOF'
# KeyPouch Docker Compose Override for HTTPS
# Use this with: docker compose -f docker-compose.yml -f ssl/docker-compose.override.yml up

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./ssl:/etc/nginx/ssl:ro
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - web
      - backend
    networks:
      - default

  web:
    ports: []  # Remove direct port exposure, go through nginx
    
  backend:
    ports: []  # Remove direct port exposure, go through nginx
EOF
    
    log "Docker Compose override created: $docker_override"
}

# Show usage
show_usage() {
    echo "KeyPouch Self-Signed SSL Certificate Generator"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN       Domain name (default: localhost)"
    echo "  -o, --org ORGANIZATION   Organization name (default: KeyPouch)"
    echo "  -e, --email EMAIL        Email address (default: admin@keypouch.local)"
    echo "  -v, --validity DAYS       Certificate validity in days (default: 365)"
    echo "  --nginx                   Generate Nginx configuration"
    echo "  --apache                  Generate Apache configuration"
    echo "  --docker                  Generate Docker Compose override"
    echo "  --all                    Generate all configurations"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Generate basic certificates"
    echo "  $0 --domain myapp.local --nginx         # Generate certs for custom domain with Nginx config"
    echo "  $0 --all                              # Generate certs and all configurations"
}

# Parse command line arguments
GENERATE_NGINX=false
GENERATE_APACHE=false
GENERATE_DOCKER=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -o|--org)
            ORGANIZATION="$2"
            shift 2
            ;;
        -e|--email)
            EMAIL="$2"
            shift 2
            ;;
        -v|--validity)
            VALIDITY_DAYS="$2"
            shift 2
            ;;
        --nginx)
            GENERATE_NGINX=true
            shift
            ;;
        --apache)
            GENERATE_APACHE=true
            shift
            ;;
        --docker)
            GENERATE_DOCKER=true
            shift
            ;;
        --all)
            GENERATE_NGINX=true
            GENERATE_APACHE=true
            GENERATE_DOCKER=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    log "Starting SSL certificate generation for KeyPouch..."
    info "Domain: $DOMAIN"
    info "Organization: $ORGANIZATION"
    info "Email: $EMAIL"
    info "Validity: $VALIDITY_DAYS days"
    
    check_openssl
    create_cert_dir
    generate_private_key
    create_csr
    generate_certificate
    generate_dh_params
    set_permissions
    display_cert_info
    
    # Generate additional configurations if requested
    if [ "$GENERATE_NGINX" = true ] || [ "$GENERATE_APACHE" = true ] || [ "$GENERATE_DOCKER" = true ]; then
        echo ""
        log "Generating additional configurations..."
        
        if [ "$GENERATE_NGINX" = true ]; then
            create_nginx_config
        fi
        
        if [ "$GENERATE_APACHE" = true ]; then
            create_apache_config
        fi
        
        if [ "$GENERATE_DOCKER" = true ]; then
            create_docker_override
        fi
    fi
    
    echo ""
    log "SSL certificate generation completed!"
    info "Certificate files created in: $CERT_DIR"
    info "Files generated:"
    echo "  - $CERT_DIR/keypouch.key (private key)"
    echo "  - $CERT_DIR/keypouch.crt (certificate)"
    echo "  - $CERT_DIR/keypouch.csr (certificate signing request)"
    echo "  - $CERT_DIR/dhparam.pem (DH parameters)"
    
    if [ "$GENERATE_NGINX" = true ]; then
        echo "  - $CERT_DIR/nginx.conf (Nginx configuration)"
    fi
    
    if [ "$GENERATE_APACHE" = true ]; then
        echo "  - $CERT_DIR/apache.conf (Apache configuration)"
    fi
    
    if [ "$GENERATE_DOCKER" = true ]; then
        echo "  - $CERT_DIR/docker-compose.override.yml (Docker override)"
    fi
    
    echo ""
    warning "Remember to add the certificate to your browser's trust store to avoid security warnings!"
}

# Run main function
main
