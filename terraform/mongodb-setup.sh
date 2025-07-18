#!/bin/bash
sudo apt-get update
sudo apt-get install -y gnupg awscli

# Import the public key for MongoDB 4.2 (an outdated version)
wget -qO - https://www.mongodb.org/static/pgp/server-4.2.asc | sudo apt-key add -

# Create a list file for MongoDB
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.2.list

sudo apt-get update
# Install MongoDB 4.2
sudo apt-get install -y mongodb-org=4.2.24 mongodb-org-server=4.2.24 mongodb-org-shell=4.2.24 mongodb-org-mongos=4.2.24 mongodb-org-tools=4.2.24

# Prevent the package from being automatically updated
echo "mongodb-org hold" | sudo dpkg --set-selections
echo "mongodb-org-server hold" | sudo dpkg --set-selections
echo "mongodb-org-shell hold" | sudo dpkg --set-selections
echo "mongodb-org-mongos hold" | sudo dpkg --set-selections
echo "mongodb-org-tools hold" | sudo dpkg --set-selections

# Start and enable MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod

# Configure MongoDB to listen on all interfaces (0.0.0.0)
sudo sed -i 's/bindIp: 127.0.0.1/bindIp: 0.0.0.0/' /etc/mongod.conf

# Restart MongoDB for the config to take effect
sudo systemctl restart mongod

# Wait for MongoDB to be ready
sleep 10

# ----------------- THIS IS THE HIGHLIGHTED CHANGE -----------------
# Create an admin user for the application with backup privileges
mongo --eval 'db.getSiblingDB("admin").createUser({user: "wizadmin", pwd: "verysecretpassword123", roles: [{role: "readWriteAnyDatabase", db: "admin"}, {role: "backup", db: "admin"}]})'
# ------------------------------------------------------------------

# FIX: Use a more robust method to enable authentication
# This appends the security settings to the config file, avoiding sed issues.
echo -e "\nsecurity:\n  authorization: enabled" | sudo tee -a /etc/mongod.conf

# Restart mongod to apply the security changes
sudo systemctl restart mongod
