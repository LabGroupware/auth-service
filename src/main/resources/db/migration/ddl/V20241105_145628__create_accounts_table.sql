CREATE TABLE accounts (
    account_id VARCHAR(100) PRIMARY KEY,
    version INTEGER DEFAULT 0 NOT NULL,
    login_id VARCHAR(200) NOT NULL UNIQUE,
    password_hash VARCHAR(200) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'USER',
    created_at date NOT NULL,
    created_by varchar(50) NOT NULL,
    updated_at date DEFAULT NULL,
    updated_by varchar(50) DEFAULT NULL
);

CREATE INDEX accounts_login_id_index ON accounts (login_id);