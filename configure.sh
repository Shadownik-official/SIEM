#!/bin/bash

# SIEM Configuration Script

echo "Configuring Enterprise SIEM Solution..."

# Load environment variables
if [ -f .env ]; then
    source .env
fi

# Generate secure keys
generate_keys() {
    echo "Generating security keys..."
    
    # Generate JWT secret
    openssl rand -base64 48 > /etc/siem/jwt_secret.key
    
    # Generate SSL certificate
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/siem/ssl.key -out /etc/siem/ssl.crt \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
}

# Configure database connections
configure_databases() {
    echo "Configuring databases..."
    
    # PostgreSQL
    psql -U postgres -d siem -f config/sql/init.sql
    
    # Elasticsearch
    curl -X PUT "localhost:9200/siem-events" -H "Content-Type: application/json" -d @config/elasticsearch/mappings.json
}

# Configure network settings
configure_network() {
    echo "Configuring network settings..."
    
    # Set up firewall rules
    if command -v ufw >/dev/null; then
        sudo ufw allow 8443/tcp  # Dashboard
        sudo ufw allow 514/tcp   # Syslog
        sudo ufw allow 514/udp   # Syslog
    elif command -v firewall-cmd >/dev/null; then
        sudo firewall-cmd --permanent --add-port=8443/tcp
        sudo firewall-cmd --permanent --add-port=514/tcp
        sudo firewall-cmd --permanent --add-port=514/udp
        sudo firewall-cmd --reload
    fi
}

# Configure logging
configure_logging() {
    echo "Configuring logging..."
    
    # Create log directories
    sudo mkdir -p /var/log/siem/events
    sudo mkdir -p /var/log/siem/audit
    sudo mkdir -p /var/log/siem/system
    
    # Set permissions
    sudo chown -R $USER:$USER /var/log/siem
    
    # Configure log rotation
    sudo cp config/logrotate/siem /etc/logrotate.d/
}

# Configure system services
configure_services() {
    echo "Configuring system services..."
    
    # Copy service files
    sudo cp config/systemd/* /etc/systemd/system/
    
    # Reload systemd
    sudo systemctl daemon-reload
    
    # Enable services
    sudo systemctl enable siem-collector
    sudo systemctl enable siem-analyzer
    sudo systemctl enable siem-api
    sudo systemctl enable siem-dashboard
}

# Initialize Docker containers
initialize_docker() {
    echo "Initializing Docker containers..."
    
    # Build containers
    docker-compose build
    
    # Create Docker networks
    docker network create siem-network || true
}

# Configure initial admin user
configure_admin() {
    echo "Configuring admin user..."
    
    # Generate admin password
    ADMIN_PASSWORD=$(openssl rand -base64 12)
    
    # Create admin user
    python3 scripts/create_admin.py --username admin --password "$ADMIN_PASSWORD"
    
    echo "Admin credentials:"
    echo "Username: admin"
    echo "Password: $ADMIN_PASSWORD"
    echo "Please change the password after first login!"
}

# Verify configuration
verify_configuration() {
    echo "Verifying configuration..."
    
    # Check services
    python3 scripts/verify_config.py
    
    # Test connections
    python3 scripts/test_connections.py
}

# Main configuration process
main() {
    generate_keys
    configure_databases
    configure_network
    configure_logging
    configure_services
    initialize_docker
    configure_admin
    verify_configuration
    
    echo "Configuration completed successfully!"
    echo "You can now start the SIEM system using 'docker-compose up -d'"
}

main
