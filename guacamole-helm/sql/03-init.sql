-- Create tables for desktop manager application

-- NOTE: PostgreSQL creates databases from a separate connection, not from within a script
-- CREATE DATABASE desktop_manager;
-- Instead, database should be created before the script is run or via docker-compose

-- Users table with OIDC support
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255),
    email VARCHAR(255) NOT NULL UNIQUE,
    organization VARCHAR(255),
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- OIDC fields
    sub VARCHAR(255) UNIQUE,  -- OIDC subject identifier
    given_name VARCHAR(255),
    family_name VARCHAR(255),
    locale VARCHAR(10),
    email_verified BOOLEAN DEFAULT FALSE,
    last_login TIMESTAMP
);

-- Keep existing indexes and add new ones
CREATE INDEX idx_username ON users(username);
CREATE INDEX idx_email ON users(email);
CREATE INDEX idx_sub ON users(sub);

-- Social Auth Association table for OIDC
CREATE TABLE IF NOT EXISTS social_auth_association (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    provider VARCHAR(32) NOT NULL,  -- e.g., 'oidc'
    provider_user_id VARCHAR(255) NOT NULL,  -- maps to 'sub' in OIDC
    provider_name VARCHAR(255),  -- e.g., 'e-infra'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP,
    extra_data JSONB,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (provider, provider_user_id)
);

-- PKCE Code Verifier table for OIDC
CREATE TABLE IF NOT EXISTS pkce_state (
    id SERIAL PRIMARY KEY,
    state VARCHAR(64) NOT NULL UNIQUE,
    code_verifier VARCHAR(128) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    used BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_state ON pkce_state(state);
CREATE INDEX idx_expires ON pkce_state(expires_at);

-- Connections table
CREATE TABLE IF NOT EXISTS connections (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255),
    guacamole_connection_id VARCHAR(255) NOT NULL,
    target_host VARCHAR(255),
    target_port INTEGER,
    password VARCHAR(255),
    protocol VARCHAR(50) DEFAULT 'vnc',
    FOREIGN KEY (created_by) REFERENCES users(username)
);
