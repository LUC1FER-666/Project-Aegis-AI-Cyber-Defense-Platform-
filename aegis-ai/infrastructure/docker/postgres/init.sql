-- =============================================================================
-- AEGIS AI — PostgreSQL Initialization
-- Runs once on first container start
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";    -- Fuzzy text search
CREATE EXTENSION IF NOT EXISTS "btree_gin";  -- GIN indexes on scalar types

-- Create schemas for logical separation
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS assets;
CREATE SCHEMA IF NOT EXISTS detections;
CREATE SCHEMA IF NOT EXISTS incidents;
CREATE SCHEMA IF NOT EXISTS intelligence;
CREATE SCHEMA IF NOT EXISTS responses;
CREATE SCHEMA IF NOT EXISTS audit;

-- Set default search path
ALTER DATABASE aegis SET search_path TO public, auth, assets, detections, incidents, intelligence, responses, audit;
