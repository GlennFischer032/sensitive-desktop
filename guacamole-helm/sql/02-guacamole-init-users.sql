-- Create default admin user (password: guacadmin)
INSERT INTO guacamole_entity (name, type) VALUES ('guacadmin', 'USER');

INSERT INTO guacamole_user (
    entity_id,
    password_hash,
    password_salt,
    password_date
) SELECT
    entity_id,
    x'CA458A7D494E3BE824F5E1E175A1556C0F8EEF2C2D7DF3633BEC4A29C4411960',  -- 'guacadmin' hashed with SHA-256
    x'FE24ADC5E11E2B25288D1704ABE67A79E342ECC26064CE69C5B3177795A82264',
    NOW()
FROM guacamole_entity WHERE name = 'guacadmin';

-- Grant admin permissions to the admin user
INSERT INTO guacamole_system_permission (
    entity_id,
    permission
) SELECT
    entity_id,
    permission
FROM (
    SELECT entity_id, 'CREATE_CONNECTION' AS permission FROM guacamole_entity WHERE name = 'guacadmin'
    UNION SELECT entity_id, 'CREATE_CONNECTION_GROUP' FROM guacamole_entity WHERE name = 'guacadmin'
    UNION SELECT entity_id, 'CREATE_SHARING_PROFILE' FROM guacamole_entity WHERE name = 'guacadmin'
    UNION SELECT entity_id, 'CREATE_USER' FROM guacamole_entity WHERE name = 'guacadmin'
    UNION SELECT entity_id, 'CREATE_USER_GROUP' FROM guacamole_entity WHERE name = 'guacadmin'
    UNION SELECT entity_id, 'ADMINISTER' FROM guacamole_entity WHERE name = 'guacadmin'
) permissions;
