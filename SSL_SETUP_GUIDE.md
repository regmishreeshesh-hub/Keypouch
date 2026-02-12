# KeyPouch SSL Setup Guide

This guide explains how to set up HTTPS for KeyPouch using self-signed certificates.

## Quick Start

### 1. Generate SSL Certificates

```bash
# Generate basic certificates
./generate-ssl.sh

# Generate certificates with custom domain and all configurations
./generate-ssl.sh --domain keypouch.local --all
```

### 2. Start KeyPouch with SSL

```bash
# Using the SSL-enabled docker-compose file
docker compose -f docker-compose.yml -f docker-compose.ssl.yml up -d
```

### 3. Access KeyPouch

- **HTTPS**: https://localhost
- **HTTP**: http://localhost (redirects to HTTPS)

## Files Created

### SSL Certificate Generator
- `generate-ssl.sh` - Main SSL certificate generation script

### Docker Configuration
- `docker-compose.ssl.yml` - Docker compose override with Nginx
- `nginx/nginx.conf` - Main Nginx configuration
- `nginx/default.conf` - SSL site configuration

### Generated Certificates (in `ssl/` directory)
- `keypouch.key` - Private key
- `keypouch.crt` - SSL certificate
- `keypouch.csr` - Certificate signing request
- `dhparam.pem` - Diffie-Hellman parameters

## Certificate Generator Options

```bash
./generate-ssl.sh [OPTIONS]

Options:
  -d, --domain DOMAIN       Domain name (default: localhost)
  -o, --org ORGANIZATION   Organization name (default: KeyPouch)
  -e, --email EMAIL        Email address (default: admin@keypouch.local)
  -v, --validity DAYS       Certificate validity in days (default: 365)
  --nginx                   Generate Nginx configuration
  --apache                  Generate Apache configuration
  --docker                  Generate Docker Compose override
  --all                    Generate all configurations
  -h, --help              Show help message
```

## Examples

### Basic Setup
```bash
# Generate certificates for localhost
./generate-ssl.sh

# Start with SSL
docker compose -f docker-compose.yml -f docker-compose.ssl.yml up -d
```

### Custom Domain Setup
```bash
# Generate for custom domain
./generate-ssl.sh --domain mykeypouch.local --all

# Update /etc/hosts (optional)
echo "127.0.0.1 mykeypouch.local" | sudo tee -a /etc/hosts

# Start with SSL
docker compose -f docker-compose.yml -f docker-compose.ssl.yml up -d
```

### Development with Different Ports
```bash
# Generate certificates
./generate-ssl.sh --domain localhost:8443

# Modify nginx/default.conf to use port 8443
# Then start:
docker compose -f docker-compose.yml -f docker-compose.ssl.yml up -d
```

## Browser Trust Setup

### Adding Certificate to Browser Trust Store

#### Chrome/Edge
1. Open Chrome Settings → Privacy and security → Manage certificates
2. Go to "Authorities" tab
3. Click "Import"
4. Select `ssl/keypouch.crt`
5. Check "Trust this certificate for identifying websites"
6. Click OK

#### Firefox
1. Open Firefox Settings → Privacy & Security → Certificates
2. Click "View Certificates"
3. Go to "Authorities" tab
4. Click "Import"
5. Select `ssl/keypouch.crt`
6. Check "Trust this CA to identify websites"
7. Click OK

#### Safari (macOS)
1. Double-click `ssl/keypouch.crt`
2. Keychain Access will open
3. Set "Trust" to "Always Trust"
4. Save changes

### Command Line (macOS/Linux)
```bash
# Add to system trust store (macOS)
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ssl/keypouch.crt

# Add to system trust store (Linux - varies by distribution)
# Ubuntu/Debian:
sudo cp ssl/keypouch.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# CentOS/RHEL:
sudo cp ssl/keypouch.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
```

## Production Considerations

### For Production Use

Self-signed certificates are suitable for development and internal use. For production:

1. **Use Let's Encrypt (Free)**
   ```bash
   # Install certbot
   sudo apt-get install certbot python3-certbot-nginx
   
   # Generate certificate
   sudo certbot --nginx -d yourdomain.com
   ```

2. **Purchase Commercial Certificate**
   - Generate CSR: `openssl req -new -key private.key -out domain.csr`
   - Submit CSR to certificate authority
   - Install received certificates

3. **Use Cloudflare SSL**
   - Sign up for Cloudflare
   - Enable "Flexible SSL" or "Full SSL"
   - Point DNS to Cloudflare

### Production Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    # Production certificates
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    # Enhanced security settings
    ssl_trusted_certificate /etc/letsencrypt/live/yourdomain.com/chain.pem;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # ... rest of configuration
}
```

## Troubleshooting

### Certificate Issues

#### "Your connection is not private"
- **Cause**: Browser doesn't trust self-signed certificate
- **Solution**: Add certificate to browser trust store (see above)

#### "NET::ERR_CERT_COMMON_NAME_INVALID"
- **Cause**: Domain mismatch
- **Solution**: Use correct domain or regenerate with correct domain

#### "SSL handshake failed"
- **Cause**: Certificate file permissions or corrupted files
- **Solution**: 
  ```bash
  chmod 600 ssl/keypouch.key
  chmod 644 ssl/keypouch.crt
  ./generate-ssl.sh  # Regenerate certificates
  ```

### Nginx Issues

#### "502 Bad Gateway"
- **Cause**: Nginx can't reach backend services
- **Solution**: Check if containers are running
  ```bash
  docker compose ps
  docker compose logs nginx
  ```

#### "404 Not Found"
- **Cause**: Incorrect proxy configuration
- **Solution**: Check nginx/default.conf paths

#### Port Conflicts
- **Cause**: Ports 80/443 already in use
- **Solution**: Stop conflicting services or change ports
  ```bash
  # Check what's using ports
  sudo netstat -tlnp | grep :80
  sudo netstat -tlnp | grep :443
  ```

### Docker Issues

#### Container won't start
```bash
# Check logs
docker compose logs nginx
docker compose logs web
docker compose logs backend

# Restart services
docker compose down
docker compose -f docker-compose.yml -f docker-compose.ssl.yml up -d
```

#### Certificate mounting issues
- **Cause**: SSL directory not found or permissions
- **Solution**: 
  ```bash
  mkdir -p ssl
  ./generate-ssl.sh
  chmod 755 ssl
  ```

## Security Best Practices

### SSL Configuration
- Use TLS 1.2 and 1.3 only
- Implement strong cipher suites
- Enable HSTS headers
- Use proper certificate chains

### Application Security
- Keep certificates updated (expire after 365 days for self-signed)
- Monitor certificate expiration
- Use strong private key protection
- Regular security audits

### Network Security
- Firewall rules to restrict access
- VPN for remote access
- Regular security updates
- Monitor access logs

## Advanced Configuration

### Multiple Domains
```bash
# Generate for multiple domains
./generate-ssl.sh --domain "keypouch.local,api.keypouch.local"
```

### Wildcard Certificate
```bash
# Generate wildcard certificate
./generate-ssl.sh --domain "*.keypouch.local"
```

### Custom CA Setup
For internal networks, consider setting up your own Certificate Authority:
- Create root CA certificate
- Sign server certificates with your CA
- Distribute CA certificate to all clients

## Monitoring and Maintenance

### Certificate Expiration
```bash
# Check certificate expiration
openssl x509 -in ssl/keypouch.crt -noout -dates

# Set up renewal reminder
echo "0 0 1 * * /path/to/keypouch/generate-ssl.sh && docker compose restart nginx" | crontab -
```

### Log Monitoring
```bash
# Monitor Nginx logs
docker compose logs -f nginx

# Monitor SSL connections
docker exec keypouch-nginx-1 tail -f /var/log/nginx/access.log | grep HTTPS
```

## Support

For issues with SSL setup:
1. Check certificate files exist and have correct permissions
2. Verify Nginx configuration syntax: `nginx -t`
3. Check Docker container logs
4. Ensure ports 80/443 are available
5. Verify domain resolution (for custom domains)
