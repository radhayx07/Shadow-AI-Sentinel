-- Shadow AI Sentinel : schema.sql  (MySQL 8.0)
-- Step 1: database design. Run this whole file in MySQL Workbench.

DROP DATABASE IF EXISTS shadow_ai_sentinel;
CREATE DATABASE shadow_ai_sentinel CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE shadow_ai_sentinel;

-- 1. Users: people who can log in
CREATE TABLE Users (
    user_id        INT AUTO_INCREMENT PRIMARY KEY,
    username       VARCHAR(50)  NOT NULL UNIQUE,
    email          VARCHAR(120) NOT NULL UNIQUE,
    password_hash  VARCHAR(255) NOT NULL,          -- hashed password, NEVER plain text
    created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 2. DetectionCategories: kinds of sensitive data (Email, Phone, ...)
CREATE TABLE DetectionCategories (
    category_id     INT AUTO_INCREMENT PRIMARY KEY,
    category_name   VARCHAR(50)  NOT NULL UNIQUE,
    severity_weight TINYINT      NOT NULL DEFAULT 1,   -- 1 = low, 2 = medium, 3 = high
    description     VARCHAR(200),
    CONSTRAINT chk_severity CHECK (severity_weight BETWEEN 1 AND 3)
) ENGINE=InnoDB;

-- 3. SecurityRules: the regex patterns used to detect each category
CREATE TABLE SecurityRules (
    rule_id        INT AUTO_INCREMENT PRIMARY KEY,
    category_id    INT          NOT NULL,
    rule_name      VARCHAR(80)  NOT NULL UNIQUE,
    regex_pattern  VARCHAR(500) NOT NULL,
    is_active      TINYINT(1)   NOT NULL DEFAULT 1,     -- 1 = enabled, 0 = disabled
    created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_rule_category FOREIGN KEY (category_id)
        REFERENCES DetectionCategories(category_id)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    INDEX idx_rules_category (category_id),
    INDEX idx_rules_active (is_active)
) ENGINE=InnoDB;

-- 4. Scans: one row per scan. The original prompt text is NOT stored.
CREATE TABLE Scans (
    scan_id       INT AUTO_INCREMENT PRIMARY KEY,
    user_id       INT NOT NULL,
    scan_time     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    risk_level    ENUM('Low','Medium','High') NOT NULL DEFAULT 'Low',
    action_taken  ENUM('Scanned only','Redacted') NOT NULL DEFAULT 'Scanned only',
    CONSTRAINT fk_scan_user FOREIGN KEY (user_id)
        REFERENCES Users(user_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_scans_user_time (user_id, scan_time),
    INDEX idx_scans_risk (risk_level)
) ENGINE=InnoDB;

-- 5. ScanFindings: which categories were found in which scan (and how many times)
CREATE TABLE ScanFindings (
    finding_id   INT AUTO_INCREMENT PRIMARY KEY,
    scan_id      INT NOT NULL,
    category_id  INT NOT NULL,
    match_count  INT NOT NULL DEFAULT 1,
    CONSTRAINT chk_match_count CHECK (match_count > 0),
    CONSTRAINT fk_finding_scan FOREIGN KEY (scan_id)
        REFERENCES Scans(scan_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_finding_category FOREIGN KEY (category_id)
        REFERENCES DetectionCategories(category_id)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    UNIQUE KEY uq_scan_category (scan_id, category_id),
    INDEX idx_findings_category (category_id)
) ENGINE=InnoDB;

-- Starting data: categories
INSERT INTO DetectionCategories (category_name, severity_weight, description) VALUES
 ('Email',       1, 'Email addresses'),
 ('Phone',       2, 'Phone numbers'),
 ('API Key',     3, 'API-key-like strings'),
 ('Credential',  3, 'Passwords and similar secrets');

-- Starting data: simple demo rules (regex is read by Python; \\ in SQL becomes \ in the database)
INSERT INTO SecurityRules (category_id, rule_name, regex_pattern) VALUES
 (1, 'Email address',     '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}'),
 (2, 'Indian mobile no.', '(\\+91[ -]?)?[6-9][0-9]{9}'),
 (3, 'API key prefix',    '(sk|pk|api|key)[-_][A-Za-z0-9_-]{16,}'),
 (4, 'Password pattern',  '(password|passwd|pwd)\\s*[:=]\\s*[^ ]+');

-- Quick check
SHOW TABLES;
SELECT 'DetectionCategories' AS table_name, COUNT(*) AS total_rows FROM DetectionCategories
UNION ALL SELECT 'SecurityRules', COUNT(*) FROM SecurityRules;
