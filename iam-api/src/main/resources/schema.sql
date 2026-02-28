-- ===========================================================================
-- Users
-- ===========================================================================
CREATE TABLE IF NOT EXISTS users
(
    username varchar(200) NOT NULL PRIMARY KEY,
    password varchar(500) NOT NULL,
    enabled  boolean      NOT NULL
);

CREATE TABLE IF NOT EXISTS usersinfo
(
    username                 varchar(200) NOT NULL PRIMARY KEY,
    isAccountNonExpired      boolean      NOT NULL,
    isAccountNonLocked       boolean      NOT NULL,
    isCredentialsNonExpired  boolean      NOT NULL,
    securityQuestion         varchar(200) NOT NULL,
    securityAnswer           varchar(200) NOT NULL,
    mfaSecret                varchar(200) NOT NULL,
    mfaKeyId                 varchar(200) NOT NULL,
    mfaEnabled               boolean      NOT NULL,
    mfaRegistered            boolean      NOT NULL,
    securityQuestionEnabled  boolean      NOT NULL,
    CONSTRAINT fk_usersinfo_users FOREIGN KEY (username) REFERENCES users (username)
);

CREATE TABLE IF NOT EXISTS authorities
(
    username  varchar(200) NOT NULL,
    authority varchar(50)  NOT NULL,
    CONSTRAINT fk_authorities_users FOREIGN KEY (username) REFERENCES users (username),
    CONSTRAINT username_authority UNIQUE (username, authority)
);

-- ---------------------------------------------------------------------------
-- Seed users  (INSERT IGNORE = skip silently if row already exists)
-- Passwords are bcrypt-encoded; plain-text value = 'password'
-- ---------------------------------------------------------------------------
INSERT IGNORE INTO users VALUES
    ('user',  '{bcrypt}$2a$14$tEnq90/CcR320dWQ.NdQLuj326PmgLzMGmFkUUOHQrbjPWplKK67i', true),
    ('admin', '{bcrypt}$2a$14$tJANh4xMR7qNjwwftmoZjezhp6rP.RVUtIFXFBF6maQvqGXwvM4JS', true);

INSERT IGNORE INTO authorities VALUES
    ('user',  'ROLE_USER'),
    ('admin', 'ROLE_USER'),
    ('admin', 'ROLE_ADMIN');

-- ===========================================================================
-- OAuth2 Registered Client Repository
-- ===========================================================================
CREATE TABLE IF NOT EXISTS oauth2_registered_client
(
    id                            varchar(100)  NOT NULL,
    client_id                     varchar(100)  NOT NULL,
    client_id_issued_at           timestamp     NULL,
    client_secret                 varchar(200)  DEFAULT NULL,
    client_secret_expires_at      timestamp     NULL,
    client_name                   varchar(200)  NOT NULL,
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types     varchar(1000) NOT NULL,
    redirect_uris                 varchar(1000) DEFAULT NULL,
    post_logout_redirect_uris     varchar(1000) DEFAULT NULL,
    scopes                        varchar(1000) NOT NULL,
    client_settings               varchar(2000) NOT NULL,
    token_settings                varchar(2000) NOT NULL,
    PRIMARY KEY (id)
);

-- ---------------------------------------------------------------------------
-- CLIENT 4 — Swagger UI client for testing the /swagger-ui/oauth2-redirect.html flow
--   client_id     : echo-spa-client
--   client_secret : none (public client for Swagger UI)
--   PKCE          : required  (require-proof-key = true)
--   grant types   : authorization_code
--   redirect_uri  : http://localhost:9000/swagger-ui/oauth2-redirect.html
-- ---------------------------------------------------------------------------
INSERT IGNORE INTO oauth2_registered_client (
    id, client_id, client_id_issued_at,
    client_secret, client_secret_expires_at,
    client_name, client_authentication_methods, authorization_grant_types,
    redirect_uris, post_logout_redirect_uris, scopes,
    client_settings, token_settings
) VALUES (
    'swagger-ui-client-id',
    'echo-spa-client',
    NOW(),
    NULL,
    NULL,
    'Swagger UI Client',
    'none',
    'authorization_code',
    'http://localhost:9000/swagger-ui/oauth2-redirect.html',
    NULL,
    'openid,profile,read',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":true,"settings.client.require-authorization-consent":true}',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000],"settings.token.device-code-time-to-live":["java.time.Duration",300.000000000]}'
);

-- ---------------------------------------------------------------------------
-- CLIENT 1 — SPA / Public client  (PKCE REQUIRED, no client_secret)
--   client_id     : spa-client
--   client_secret : none  (public client)
--   PKCE          : required  (require-proof-key = true)
--   grant types   : authorization_code, refresh_token
--   redirect_uri  : http://localhost:3000/callback
-- ---------------------------------------------------------------------------
INSERT IGNORE INTO oauth2_registered_client (
    id, client_id, client_id_issued_at,
    client_secret, client_secret_expires_at,
    client_name, client_authentication_methods, authorization_grant_types,
    redirect_uris, post_logout_redirect_uris, scopes,
    client_settings, token_settings
) VALUES (
    'spa-client-id',
    'spa-client',
    NOW(),
    NULL,
    NULL,
    'Echo SPA Client (PKCE required)',
    'none',
    'authorization_code,refresh_token',
    'http://localhost:3000/callback',
    'http://localhost:3000/logged-out',
    'openid,profile',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":true,"settings.client.require-authorization-consent":true}',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000],"settings.token.device-code-time-to-live":["java.time.Duration",300.000000000]}'
);

-- ---------------------------------------------------------------------------
-- CLIENT 2 — Server-side / Confidential client  (PKCE OPTIONAL)
--   client_id     : server-client
--   client_secret : secret   (bcrypt hash below)
--   PKCE          : optional  (require-proof-key = false)
--   grant types   : authorization_code, refresh_token, client_credentials
--   redirect_uri  : http://127.0.0.1:8080/login/oauth2/code/client
-- ---------------------------------------------------------------------------
INSERT IGNORE INTO oauth2_registered_client (
    id, client_id, client_id_issued_at,
    client_secret, client_secret_expires_at,
    client_name, client_authentication_methods, authorization_grant_types,
    redirect_uris, post_logout_redirect_uris, scopes,
    client_settings, token_settings
) VALUES (
    'server-client-id',
    'server-client',
    NOW(),
    '{bcrypt}$2a$14$k4M/IICUdwmeTk0/nByDqee/dZ3YRPK6KlHHqEcIKUfVZR3R8.AX6',
    NULL,
    'Echo Server Client (PKCE optional)',
    'client_secret_basic',
    'authorization_code,refresh_token,client_credentials',
    'http://127.0.0.1:8080/login/oauth2/code/client',
    'http://127.0.0.1:8080/logged-out',
    'openid,profile',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":true}',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000],"settings.token.device-code-time-to-live":["java.time.Duration",300.000000000]}'
);

-- ---------------------------------------------------------------------------
-- CLIENT 3 — SpringBootClient compatibility
--   client_id     : client
--   client_secret : secret   (bcrypt hash below; same as server-client)
--   PKCE          : optional  (SpringBootClient always sends PKCE via
--                   OAuth2AuthorizationRequestCustomizers.withPkce())
--   grant types   : authorization_code, refresh_token
--   redirect_uri  : http://127.0.0.1:8080/login/oauth2/code/client
-- ---------------------------------------------------------------------------
INSERT IGNORE INTO oauth2_registered_client (
    id, client_id, client_id_issued_at,
    client_secret, client_secret_expires_at,
    client_name, client_authentication_methods, authorization_grant_types,
    redirect_uris, post_logout_redirect_uris, scopes,
    client_settings, token_settings
) VALUES (
    'client-id',
    'client',
    NOW(),
    '{bcrypt}$2a$14$k4M/IICUdwmeTk0/nByDqee/dZ3YRPK6KlHHqEcIKUfVZR3R8.AX6',
    NULL,
    'Spring Boot Client',
    'client_secret_basic',
    'authorization_code,refresh_token',
    'http://127.0.0.1:8080/login/oauth2/code/client',
    'http://127.0.0.1:8080/logged-out',
    'openid,profile',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":true}',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000],"settings.token.device-code-time-to-live":["java.time.Duration",300.000000000]}'
);

-- ===========================================================================
-- Spring Session (JDBC-backed HTTP sessions)
-- ===========================================================================
CREATE TABLE IF NOT EXISTS SPRING_SESSION (
    PRIMARY_ID           CHAR(36)     NOT NULL,
    SESSION_ID           CHAR(36)     NOT NULL,
    CREATION_TIME        BIGINT       NOT NULL,
    LAST_ACCESS_TIME     BIGINT       NOT NULL,
    MAX_INACTIVE_INTERVAL INT         NOT NULL,
    EXPIRY_TIME          BIGINT       NOT NULL,
    PRINCIPAL_NAME       VARCHAR(100),
    CONSTRAINT SPRING_SESSION_PK PRIMARY KEY (PRIMARY_ID)
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;

CREATE TABLE IF NOT EXISTS SPRING_SESSION_ATTRIBUTES (
    SESSION_PRIMARY_ID CHAR(36)     NOT NULL,
    ATTRIBUTE_NAME     VARCHAR(200) NOT NULL,
    ATTRIBUTE_BYTES    BLOB         NOT NULL,
    CONSTRAINT SPRING_SESSION_ATTRIBUTES_PK PRIMARY KEY (SESSION_PRIMARY_ID, ATTRIBUTE_NAME),
    CONSTRAINT SPRING_SESSION_ATTRIBUTES_FK FOREIGN KEY (SESSION_PRIMARY_ID)
        REFERENCES SPRING_SESSION (PRIMARY_ID) ON DELETE CASCADE
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;

-- ===========================================================================
-- OAuth2 Authorization  (issued codes + tokens)
-- ===========================================================================
CREATE TABLE IF NOT EXISTS oauth2_authorization (
    id                            varchar(100) NOT NULL,
    registered_client_id          varchar(100) NOT NULL,
    principal_name                varchar(200) NOT NULL,
    authorization_grant_type      varchar(100) NOT NULL,
    authorized_scopes             varchar(1000) DEFAULT NULL,
    attributes                    text          DEFAULT NULL,
    state                         varchar(500)  DEFAULT NULL,
    authorization_code_value      text          DEFAULT NULL,
    authorization_code_issued_at  timestamp     NULL,
    authorization_code_expires_at timestamp     NULL,
    authorization_code_metadata   text          DEFAULT NULL,
    access_token_value            text          DEFAULT NULL,
    access_token_issued_at        timestamp     NULL,
    access_token_expires_at       timestamp     NULL,
    access_token_metadata         text          DEFAULT NULL,
    access_token_type             varchar(100)  DEFAULT NULL,
    access_token_scopes           varchar(1000) DEFAULT NULL,
    oidc_id_token_value           text          DEFAULT NULL,
    oidc_id_token_issued_at       timestamp     NULL,
    oidc_id_token_expires_at      timestamp     NULL,
    oidc_id_token_metadata        text          DEFAULT NULL,
    refresh_token_value           text          DEFAULT NULL,
    refresh_token_issued_at       timestamp     NULL,
    refresh_token_expires_at      timestamp     NULL,
    refresh_token_metadata        text          DEFAULT NULL,
    user_code_value               text          DEFAULT NULL,
    user_code_issued_at           timestamp     NULL,
    user_code_expires_at          timestamp     NULL,
    user_code_metadata            text          DEFAULT NULL,
    device_code_value             text          DEFAULT NULL,
    device_code_issued_at         timestamp     NULL,
    device_code_expires_at        timestamp     NULL,
    device_code_metadata          text          DEFAULT NULL,
    PRIMARY KEY (id)
);

-- ===========================================================================
-- OAuth2 Authorization Consent
-- ===========================================================================
CREATE TABLE IF NOT EXISTS oauth2_authorization_consent (
    registered_client_id varchar(100)  NOT NULL,
    principal_name       varchar(200)  NOT NULL,
    authorities          varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);

-- ===========================================================================
-- RSA Key Pairs  (rotating JWT signing keys)
-- ===========================================================================
CREATE TABLE IF NOT EXISTS rsa_key_pairs
(
    id          varchar(500) NOT NULL PRIMARY KEY,
    private_key text          NOT NULL,
    public_key  text          NOT NULL,
    created     date          NOT NULL,
    CONSTRAINT id_created UNIQUE (id, created)
);
