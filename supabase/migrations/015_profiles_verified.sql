-- ============================================================
-- 015_profiles_verified.sql
--
-- Documentation migration — profiles.verified column was added
-- manually to the live database. This file records the change
-- so it is version-controlled alongside the rest of the
-- migrations.
--
-- The verified flag is set to true after KYC video review
-- (Phase 2 / P3-1). All existing rows default to false.
--
-- Safe to re-run: ADD COLUMN IF NOT EXISTS is a no-op when
-- the column already exists.
-- ============================================================

ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT false;
