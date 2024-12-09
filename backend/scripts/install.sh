#!/bin/bash

# SIEM Installation Script

echo "Installing Enterprise SIEM Solution..."

# Check system requirements
check_requirements() {
    echo "Checking system requirements..."
    
    # Check CPU cores
    cpu_cores=$(nproc)
    if [ $cpu_cores -lt 8 ]; then
        echo "Warning: Recommended CPU cores is 8+, found $cpu_cores"
    fi
    
    # Check RAM
    total_ram=$(free -g | awk '/^Mem:/{print $2}')
    if [ $total_ram -lt 32 ]; then
        echo "Warning: Recommended RAM is 32GB+, found ${total_ram}GB"
    fi
    
    # Check disk space
    free_space=$(df -BG / | awk '/^\//{print $4}' | tr -d 'G')
    if [ $free_space -lt 500 ]; then
        echo "Warning: Recommended free space is 500GB+, found ${free_space}GB"
    fi
}

# Install dependencies based on OS
install_dependencies() {
    echo "Installing dependencies..."
    
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu
        sudo apt-get update
        sudo apt-get install -y \
            python3.9 python3.9-dev python3-pip \
            nodejs npm \
            postgresql-13 \
            redis-server \
            docker.io docker-compose
            
    elif [ -f /etc/redhat-release ]; then
        # RHEL/CentOS
        sudo yum update -y
        sudo yum install -y \
            python39 python39-devel python39-pip \
            nodejs npm \
            postgresql13-server \
            redis \
            docker docker-compose
            
    elif [ -f /etc/os-release ] && grep -q "ID=fedora" /etc/os-release; then
        # Fedora
        sudo dnf update -y
        sudo dnf install -y \
            python39 python39-devel python39-pip \
            nodejs npm \
            postgresql13-server \
            redis \
            docker docker-compose
    else
        echo "Unsupported operating system"
        exit 1
    fi
}

# Install Python dependencies
install_python_packages() {
    echo "Installing Python packages..."
    pip3 install -r requirements.txt
}

# Install Node.js dependencies
install_node_packages() {
    echo "Installing Node.js packages..."
    cd src/dashboard
    npm install
    cd ../..
}

# Setup databases
setup_databases() {
    echo "Setting up databases..."
    
    # PostgreSQL
    if [ -f /etc/debian_version ]; then
        sudo systemctl start postgresql
        sudo -u postgres createdb siem
    else
        sudo postgresql-setup --initdb
        sudo systemctl start postgresql
        sudo -u postgres createdb siem
    fi
    
    # Redis
    sudo systemctl start redis
    
    # Elasticsearch
    sudo systemctl start elasticsearch
}

# Configure services
configure_services() {
    echo "Configuring services..."
    
    # Create necessary directories
    sudo mkdir -p /var/log/siem
    sudo mkdir -p /etc/siem
    
    # Copy configuration files
    sudo cp config/* /etc/siem/
    
    # Set permissions
    sudo chown -R $USER:$USER /var/log/siem
    sudo chown -R $USER:$USER /etc/siem
}

# Main installation process
main() {
    check_requirements
    install_dependencies
    install_python_packages
    install_node_packages
    setup_databases
    configure_services
    
    echo "Installation completed successfully!"
    echo "Please run './configure.sh' to complete the setup."
}

main
