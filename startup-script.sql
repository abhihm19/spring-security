-- ============================================================
-- Spring Security JWT Auth - Database Setup Script
-- ============================================================

-- Drop tables in correct order (respecting foreign keys)
DROP TABLE IF EXISTS `refresh_tokens`;
DROP TABLE IF EXISTS `users_roles`;
DROP TABLE IF EXISTS `roles`;
DROP TABLE IF EXISTS `users`;

-- ============================================================
-- USERS table
-- ============================================================
CREATE TABLE `users` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  `username` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `token_version` int NOT NULL DEFAULT 0,
  `created_by` int NOT NULL DEFAULT 0,
  `creation_date` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `last_updated_by` int NOT NULL DEFAULT 0,
  `last_updated_date` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_users_email` (`email`),
  UNIQUE KEY `uk_users_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- ROLES table
-- ============================================================
CREATE TABLE `roles` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `is_active` bit(1) NOT NULL DEFAULT b'1',
  `created_by` int NOT NULL DEFAULT 0,
  `creation_date` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `last_updated_by` int NOT NULL DEFAULT 0,
  `last_updated_date` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_roles_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- USERS_ROLES (many-to-many with effective dates)
-- ============================================================
CREATE TABLE `users_roles` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `role_id` bigint NOT NULL,
  `effective_start_date` datetime(6) NOT NULL,
  `effective_end_date` datetime(6) NOT NULL,
  `created_by` int NOT NULL DEFAULT 0,
  `creation_date` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `last_updated_by` int NOT NULL DEFAULT 0,
  `last_updated_date` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  KEY `fk_users_roles_user` (`user_id`),
  KEY `fk_users_roles_role` (`role_id`),
  CONSTRAINT `fk_users_roles_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_users_roles_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- REFRESH_TOKENS table (hashed tokens, rotation, reuse detection)
-- ============================================================
CREATE TABLE `refresh_tokens` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `token_hash` varchar(128) NOT NULL,
  `jti` varchar(64) NOT NULL,
  `expiry_date` datetime(6) NOT NULL,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `revoked` tinyint(1) NOT NULL DEFAULT 0,
  `revoked_at` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_refresh_tokens_hash` (`token_hash`),
  KEY `fk_refresh_tokens_user` (`user_id`),
  CONSTRAINT `fk_refresh_tokens_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- Seed data: default roles
-- ============================================================
INSERT INTO `roles` (`name`, `is_active`, `created_by`, `creation_date`, `last_updated_by`, `last_updated_date`)
VALUES
  ('USER',  b'1', 0, NOW(6), 0, NOW(6)),
  ('ADMIN', b'1', 0, NOW(6), 0, NOW(6));

-- ============================================================
-- (Optional) Seed admin user - password is BCrypt hash of "admin123"
-- ============================================================
-- INSERT INTO `users` (`name`, `username`, `email`, `password`, `token_version`, `created_by`, `creation_date`, `last_updated_by`, `last_updated_date`)
-- VALUES ('Admin User', 'admin', 'admin@example.com', '$2a$10$N9qo8uLOickgx2ZMRZoMy.MqrqLLB1v0YtXb1e1DgD7iRq6Yh0X2G', 0, 0, NOW(6), 0, NOW(6));
