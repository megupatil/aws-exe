#!/bin/bash

# Get the current date for the backup file name
DATE=$(date +"%Y-%m-%d-%H%M")

# The S3 bucket to store backups
S3_BUCKET="wiz-exercise-db-backups-c4900e21d3915fb7"

# The directory to store the backup locally before uploading
BACKUP_DIR="/home/ubuntu/backups"

# Create the backup directory if it doesn't exist
mkdir -p $BACKUP_DIR

# Run mongodump to create the backup, including authentication details
mongodump --username wizadmin --password verysecretpassword123 --authenticationDatabase admin --out $BACKUP_DIR/$DATE

# Upload the backup to S3
aws s3 cp $BACKUP_DIR/$DATE s3://$S3_BUCKET/$DATE --recursive

# Clean up the local backup file
rm -rf $BACKUP_DIR/$DATE
