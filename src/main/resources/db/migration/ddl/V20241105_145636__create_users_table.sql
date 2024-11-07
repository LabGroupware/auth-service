CREATE TABLE users (
    user_id VARCHAR(100) PRIMARY KEY,
    account_id VARCHAR(100) NOT NULL UNIQUE,
    version INTEGER DEFAULT 0 NOT NULL,
    name VARCHAR(200) NOT NULL,
    email VARCHAR(200) NOT NULL,
    given_name VARCHAR(100),
    family_name VARCHAR(100),
    middle_name VARCHAR(100),
    nickname VARCHAR(100),
    preferred_username VARCHAR(100),
    address TEXT,
    profile TEXT,
    picture TEXT,
    website TEXT,
    phone VARCHAR(15),
    gender CHAR(1),
    birthdate DATE,
    zoneinfo VARCHAR(50),
    locale VARCHAR(10),
    created_at DATE NOT NULL,
    created_by VARCHAR(50) NOT NULL,
    updated_at DATE DEFAULT NULL,
    updated_by VARCHAR(50) DEFAULT NULL,

    -- 外部キー制約: accounts テーブルの user_id に紐づけ、CASCADEオプションを設定
    CONSTRAINT fk_user_account FOREIGN KEY (account_id) REFERENCES accounts(account_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

CREATE INDEX idx_users_account_id ON users (account_id);