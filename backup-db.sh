#!/bin/bash

# KeyPouch PostgreSQL Backup Script
# This script creates automated backups of the KeyPouch database

# Configuration
DB_NAME="keypouch"
DB_USER="admin"
DB_PASSWORD="admin"
DB_HOST="localhost"
DB_PORT="5435"
BACKUP_DIR="./backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/keypouch_backup_${TIMESTAMP}.sql"
COMPRESSED_FILE="${BACKUP_FILE}.gz"
RETENTION_DAYS=30

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

# Create backup directory if it doesn't exist
create_backup_dir() {
    if [ ! -d "$BACKUP_DIR" ]; then
        log "Creating backup directory: $BACKUP_DIR"
        mkdir -p "$BACKUP_DIR"
    fi
}

# Check if PostgreSQL container is running
check_container() {
    log "Checking if KeyPouch database container is running..."
    
    if docker ps | grep -q "keypouch-db\|postgres"; then
        log "Database container is running"
        return 0
    else
        error "Database container is not running. Please start KeyPouch first with: docker compose up -d"
        exit 1
    fi
}

# Create database backup
create_backup() {
    log "Starting database backup..."
    
    # Use docker exec to run pg_dump inside the container
    if docker exec keypouch-db-1 pg_dump -U "$DB_USER" -d "$DB_NAME" > "$BACKUP_FILE" 2>/dev/null; then
        log "Database backup created successfully: $BACKUP_FILE"
        
        # Compress the backup
        gzip "$BACKUP_FILE"
        log "Backup compressed: $COMPRESSED_FILE"
        
        # Get file size
        FILE_SIZE=$(du -h "$COMPRESSED_FILE" | cut -f1)
        log "Backup size: $FILE_SIZE"
        
        return 0
    else
        error "Failed to create database backup"
        rm -f "$BACKUP_FILE" 2>/dev/null
        exit 1
    fi
}

# Clean old backups
cleanup_old_backups() {
    log "Cleaning up backups older than $RETENTION_DAYS days..."
    
    DELETED_COUNT=$(find "$BACKUP_DIR" -name "keypouch_backup_*.sql.gz" -type f -mtime +$RETENTION_DAYS -delete -print | wc -l)
    
    if [ "$DELETED_COUNT" -gt 0 ]; then
        log "Deleted $DELETED_COUNT old backup files"
    else
        log "No old backups to delete"
    fi
}

# List available backups
list_backups() {
    log "Available backups:"
    if [ -d "$BACKUP_DIR" ] && [ "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
        ls -lh "$BACKUP_DIR"/keypouch_backup_*.sql.gz 2>/dev/null | while read -r line; do
            echo "  $line"
        done
    else
        warning "No backups found in $BACKUP_DIR"
    fi
}

# Restore database from backup
restore_backup() {
    local backup_file="$1"
    
    if [ -z "$backup_file" ]; then
        error "Please specify a backup file to restore"
        echo "Usage: $0 restore <backup_file>"
        exit 1
    fi
    
    if [ ! -f "$backup_file" ]; then
        error "Backup file not found: $backup_file"
        exit 1
    fi
    
    warning "This will replace the current database with the backup from: $backup_file"
    read -p "Are you sure you want to continue? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        log "Restore operation cancelled"
        exit 0
    fi
    
    log "Starting database restore..."
    
    # Decompress if needed
    if [[ "$backup_file" == *.gz ]]; then
        TEMP_SQL="${backup_file%.gz}"
        gunzip -c "$backup_file" > "$TEMP_SQL"
        RESTORE_FILE="$TEMP_SQL"
    else
        RESTORE_FILE="$backup_file"
    fi
    
    # Drop and recreate database
    log "Dropping existing database..."
    docker exec keypouch-db-1 psql -U "$DB_USER" -c "DROP DATABASE IF EXISTS $DB_NAME;" 2>/dev/null
    
    log "Creating new database..."
    docker exec keypouch-db-1 psql -U "$DB_USER" -c "CREATE DATABASE $DB_NAME;" 2>/dev/null
    
    # Restore from backup
    if docker exec -i keypouch-db-1 psql -U "$DB_USER" -d "$DB_NAME" < "$RESTORE_FILE" 2>/dev/null; then
        log "Database restored successfully from: $backup_file"
        
        # Clean up temp file if created
        if [ -n "$TEMP_SQL" ] && [ -f "$TEMP_SQL" ]; then
            rm -f "$TEMP_SQL"
        fi
    else
        error "Failed to restore database"
        
        # Clean up temp file if created
        if [ -n "$TEMP_SQL" ] && [ -f "$TEMP_SQL" ]; then
            rm -f "$TEMP_SQL"
        fi
        exit 1
    fi
}

# Show usage
show_usage() {
    echo "KeyPouch PostgreSQL Backup Script"
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  backup              Create a new database backup (default)"
    echo "  restore <file>      Restore database from backup file"
    echo "  list                List all available backups"
    echo "  cleanup             Clean up old backups (older than $RETENTION_DAYS days)"
    echo "  help                Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                              # Create a backup"
    echo "  $0 backup                        # Create a backup"
    echo "  $0 restore backups/keypouch_backup_20240101_120000.sql.gz"
    echo "  $0 list                          # List backups"
    echo "  $0 cleanup                       # Clean old backups"
    echo ""
    echo "Configuration:"
    echo "  Database: $DB_NAME"
    echo "  Host: $DB_HOST:$DB_PORT"
    echo "  User: $DB_USER"
    echo "  Backup Directory: $BACKUP_DIR"
    echo "  Retention Days: $RETENTION_DAYS"
}

# Main script logic
main() {
    case "${1:-backup}" in
        "backup")
            check_container
            create_backup_dir
            create_backup
            cleanup_old_backups
            list_backups
            ;;
        "restore")
            check_container
            restore_backup "$2"
            ;;
        "list")
            list_backups
            ;;
        "cleanup")
            cleanup_old_backups
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            error "Unknown command: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
