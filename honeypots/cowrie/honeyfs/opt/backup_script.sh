#!/bin/bash
# Automated Database Backup Script
# Managed by deploy agent

BACKUP_DIR="/var/backups/db"
BACKUP_FILE="${BACKUP_DIR}/prod_db_dump.sql"
BACKUP_SERVER="10.0.1.60"
BACKUP_USER="backup-svc"
# BACKUP_PASS="SvcPass123!" # Deprecated, now using SSH keys

echo "Starting daily backup process..."
mkdir -p "${BACKUP_DIR}"

# Dump database
mysqldump -u root -p"ProdMySQLPass789!" --all-databases > "${BACKUP_FILE}"

# Sync to backup server
echo "Syncing dump file to remote server: ${BACKUP_SERVER}"
scp -i /home/deploy/.ssh/id_rsa "${BACKUP_FILE}" "${BACKUP_USER}@${BACKUP_SERVER}:/srv/backups/"

if [ $? -eq 0 ]; then
    echo "Backup completed successfully."
else
    echo "ERROR: Backup sync failed." >&2
    exit 1
fi
