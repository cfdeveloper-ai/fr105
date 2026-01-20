#!/bin/bash

# Script to open ports 10-10000 using UFW
# Run this script with sudo privileges

echo "Opening ports 10-10000..."

# Open TCP ports 10-10000
echo "Opening TCP ports 10-10000..."
sudo ufw allow 10:10000/tcp

# Open UDP ports 10-10000
echo "Opening UDP ports 10-10000..."
sudo ufw allow 10:10000/udp

# Check the status
echo ""
echo "Current UFW status:"
sudo ufw status

echo ""
echo "Ports 10-10000 (TCP and UDP) have been opened!"