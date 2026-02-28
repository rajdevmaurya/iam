-- ===========================================================================
-- SpringResourceServer01 — user_db schema
-- Managed by Spring SQL init (spring.sql.init.mode: always)
-- CREATE TABLE IF NOT EXISTS guards idempotency
-- ===========================================================================

CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(200) NOT NULL PRIMARY KEY,
    password VARCHAR(500) NOT NULL,
    enabled  BOOLEAN      NOT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS authorities (
    username  VARCHAR(200) NOT NULL,
    authority VARCHAR(50)  NOT NULL,
    CONSTRAINT fk_auth_users FOREIGN KEY (username) REFERENCES users (username),
    CONSTRAINT uq_username_authority UNIQUE (username, authority)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS roles (
    id   INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
    role VARCHAR(100) NOT NULL,
    CONSTRAINT uq_role UNIQUE (role)
) ENGINE=InnoDB;

-- Seed default roles (INSERT IGNORE = skip silently if row already exists)
INSERT IGNORE INTO roles (role) VALUES ('ROLE_USER'), ('ROLE_ADMIN');
