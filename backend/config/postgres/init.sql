-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "hstore";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS siem;
CREATE SCHEMA IF NOT EXISTS audit;

-- Create users table
CREATE TABLE IF NOT EXISTS siem.users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    role VARCHAR(50) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create roles table
CREATE TABLE IF NOT EXISTS siem.roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create alert_rules table
CREATE TABLE IF NOT EXISTS siem.alert_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    condition JSONB NOT NULL,
    severity VARCHAR(50) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_by UUID REFERENCES siem.users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create alerts table
CREATE TABLE IF NOT EXISTS siem.alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id UUID REFERENCES siem.alert_rules(id),
    event_ids JSONB NOT NULL,
    severity VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    assigned_to UUID REFERENCES siem.users(id),
    resolved_by UUID REFERENCES siem.users(id),
    resolution_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create assets table
CREATE TABLE IF NOT EXISTS siem.assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    ip_address INET,
    mac_address MACADDR,
    os_type VARCHAR(50),
    os_version VARCHAR(50),
    location VARCHAR(255),
    owner UUID REFERENCES siem.users(id),
    tags JSONB,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create vulnerabilities table
CREATE TABLE IF NOT EXISTS siem.vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID REFERENCES siem.assets(id),
    cve_id VARCHAR(50),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(50) NOT NULL,
    cvss_score DECIMAL(3,1),
    status VARCHAR(50) NOT NULL,
    discovered_at TIMESTAMP WITH TIME ZONE,
    patched_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create audit.events table
CREATE TABLE IF NOT EXISTS audit.events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES siem.users(id),
    event_type VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    action VARCHAR(50) NOT NULL,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON siem.alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON siem.alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON siem.alerts(severity);
CREATE INDEX IF NOT EXISTS idx_assets_ip_address ON siem.assets(ip_address);
CREATE INDEX IF NOT EXISTS idx_assets_type ON siem.assets(type);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_asset_id ON siem.vulnerabilities(asset_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON siem.vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_audit_events_user_id ON audit.events(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit.events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit.events(created_at);

-- Create default roles
INSERT INTO siem.roles (name, description, permissions) VALUES
    ('admin', 'Administrator with full access', '{"*": ["*"]}'),
    ('analyst', 'Security analyst with read/write access to alerts and events', '{"alerts": ["read", "write"], "events": ["read"]}'),
    ('user', 'Regular user with limited read access', '{"alerts": ["read"], "events": ["read"]}')
ON CONFLICT (name) DO NOTHING;

-- Create default admin user (password: changeme)
INSERT INTO siem.users (username, email, password_hash, role, first_name, last_name)
VALUES ('admin', 'admin@localhost', crypt('changeme', gen_salt('bf')), 'admin', 'System', 'Administrator')
ON CONFLICT (username) DO NOTHING;
