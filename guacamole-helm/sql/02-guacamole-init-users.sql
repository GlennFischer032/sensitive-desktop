-- Create default admin user (password: guacadmin)
INSERT INTO guacamole_entity (name, type) VALUES ('guacadmin', 'USER');

INSERT INTO guacamole_user (
    entity_id,
    password_hash,
    password_salt,
    password_date
) SELECT
    entity_id,
    decode('CA458A7D494E3BE824F5E1E175A1556C0F8EEF2C2D7DF3633BEC4A29C4411960', 'hex'),  -- 'guacadmin' hashed with SHA-256
    decode('FE24ADC5E11E2B25288D1704ABE67A79E342ECC26064CE69C5B3177795A82264', 'hex'),
    CURRENT_TIMESTAMP
FROM guacamole_entity WHERE name = 'guacadmin';

-- Grant admin permissions to the admin user
INSERT INTO guacamole_system_permission (
    entity_id,
    permission
) VALUES
    ((SELECT entity_id FROM guacamole_entity WHERE name = 'guacadmin'), 'CREATE_CONNECTION'::guacamole_system_permission_type),
    ((SELECT entity_id FROM guacamole_entity WHERE name = 'guacadmin'), 'CREATE_CONNECTION_GROUP'::guacamole_system_permission_type),
    ((SELECT entity_id FROM guacamole_entity WHERE name = 'guacadmin'), 'CREATE_SHARING_PROFILE'::guacamole_system_permission_type),
    ((SELECT entity_id FROM guacamole_entity WHERE name = 'guacadmin'), 'CREATE_USER'::guacamole_system_permission_type),
    ((SELECT entity_id FROM guacamole_entity WHERE name = 'guacadmin'), 'CREATE_USER_GROUP'::guacamole_system_permission_type),
    ((SELECT entity_id FROM guacamole_entity WHERE name = 'guacadmin'), 'ADMINISTER'::guacamole_system_permission_type);
