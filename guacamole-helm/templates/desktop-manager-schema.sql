-- Create desktop_manager database
CREATE DATABASE IF NOT EXISTS desktop_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Grant privileges to the guacamole user
GRANT ALL PRIVILEGES ON desktop_manager.* TO '{{ .Values.mysql.user }}'@'%';
FLUSH PRIVILEGES;

USE desktop_manager;

-- Create configurations table
CREATE TABLE IF NOT EXISTS configurations (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    helm_chart_path VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create connections table
CREATE TABLE IF NOT EXISTS connections (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) UNIQUE NOT NULL,
    ip_address VARCHAR(255) NOT NULL,
    connection_id VARCHAR(255) NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    configuration_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (configuration_id) REFERENCES configurations(id)
);

-- Create user_configurations table for many-to-many relationship
CREATE TABLE IF NOT EXISTS user_configurations (
    user_id INT,
    configuration_id INT,
    PRIMARY KEY (user_id, configuration_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (configuration_id) REFERENCES configurations(id)
);
