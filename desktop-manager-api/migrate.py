from database import Base, engine
from sqlalchemy import text

def migrate():
    # Drop and recreate the connections table
    with engine.connect() as conn:
        conn.execute(text('DROP TABLE IF EXISTS connections'))
        conn.execute(text('''
            CREATE TABLE connections (
                id INTEGER NOT NULL AUTO_INCREMENT,
                name VARCHAR(255) NOT NULL,
                created_at DATETIME,
                created_by VARCHAR(255),
                guacamole_connection_id VARCHAR(255) NOT NULL,
                PRIMARY KEY (id),
                FOREIGN KEY(created_by) REFERENCES users (username)
            )
        '''))
        conn.commit()

if __name__ == '__main__':
    migrate()
