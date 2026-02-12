# KeyPouch Database Backup Guide

This guide explains how to use the PostgreSQL backup script for KeyPouch.

## Files Created

- `backup-db.sh` - Main backup script
- `cron-backup.example` - Example cron job configuration for automated backups

## Quick Start

### Manual Backup

```bash
# Create a backup (default command)
./backup-db.sh

# Or explicitly
./backup-db.sh backup
```

### List Backups

```bash
./backup-db.sh list
```

### Restore from Backup

```bash
./backup-db.sh restore backups/keypouch_backup_20240101_120000.sql.gz
```

### Clean Old Backups

```bash
./backup-db.sh cleanup
```

## Features

- **Automated Compression**: Backups are automatically compressed with gzip
- **Container Detection**: Checks if the database container is running
- **Retention Policy**: Automatically deletes backups older than 30 days
- **Safe Restore**: Confirms before restoring to prevent accidental data loss
- **Colored Output**: Easy-to-read logging with color coding
- **Error Handling**: Comprehensive error checking and reporting

## Configuration

The script uses the following configuration (can be modified in `backup-db.sh`):

```bash
DB_NAME="keypouch"          # Database name
DB_USER="admin"             # Database user
DB_PASSWORD="admin"         # Database password
DB_HOST="localhost"         # Database host
DB_PORT="5435"             # Database port
BACKUP_DIR="./backups"     # Backup directory
RETENTION_DAYS=30           # Days to keep backups
```

## Automated Backups

### Using Cron

1. Open crontab editor:
   ```bash
   crontab -e
   ```

2. Add one of the examples from `cron-backup.example`:
   ```bash
   # Daily backup at 2:00 AM
   0 2 * * * /home/shree/Keypouch/backup-db.sh backup >/dev/null 2>&1
   ```

### Using Systemd Timer (Alternative)

Create a systemd service and timer for more robust scheduling:

```bash
# Create service file
sudo tee /etc/systemd/system/keypouch-backup.service > /dev/null <<EOF
[Unit]
Description=KeyPouch Database Backup
After=docker.service

[Service]
Type=oneshot
User=$USER
WorkingDirectory=/home/shree/Keypouch
ExecStart=/home/shree/Keypouch/backup-db.sh backup
EOF

# Create timer file
sudo tee /etc/systemd/system/keypouch-backup.timer > /dev/null <<EOF
[Unit]
Description=Run KeyPouch backup daily
Requires=keypouch-backup.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable and start the timer
sudo systemctl enable keypouch-backup.timer
sudo systemctl start keypouch-backup.timer
```

## Backup File Format

Backups are saved with the following naming convention:
```
backups/keypouch_backup_YYYYMMDD_HHMMSS.sql.gz
```

Example: `backups/keypouch_backup_20240101_120000.sql.gz`

## Restore Process

The restore process:
1. Drops the existing database
2. Creates a fresh database
3. Restores data from the backup file
4. Requires explicit confirmation before proceeding

**Warning**: This will completely replace the current database contents!

## Troubleshooting

### Container Not Running
```
ERROR: Database container is not running. Please start KeyPouch first with: docker compose up -d
```
**Solution**: Start the KeyPouch application first.

### Permission Denied
```
ERROR: Failed to create database backup
```
**Solution**: Ensure the script is executable and you have Docker permissions:
```bash
chmod +x backup-db.sh
sudo usermod -aG docker $USER
```

### Disk Space
Monitor backup directory size:
```bash
du -sh backups/
```

### Manual Database Access
Connect directly to the database:
```bash
docker exec -it keypouch-db-1 psql -U admin -d keypouch
```

## Best Practices

1. **Regular Backups**: Set up automated daily backups
2. **Test Restores**: Periodically test restore process on a test environment
3. **Off-site Storage**: Consider copying backups to cloud storage or another location
4. **Monitor Logs**: Check backup logs regularly for errors
5. **Retention Policy**: Adjust retention days based on storage capacity and compliance needs

## Example Backup Workflow

```bash
# 1. Start KeyPouch
docker compose up -d

# 2. Create initial backup
./backup-db.sh backup

# 3. List backups
./backup-db.sh list

# 4. Set up automated backups
crontab -e
# Add: 0 2 * * * /home/shree/Keypouch/backup-db.sh backup >/dev/null 2>&1

# 5. Test restore (if needed)
./backup-db.sh restore backups/keypouch_backup_20240101_120000.sql.gz
```
