-- ============================================================
-- 004_add_privacy_column.sql
--
-- Adds a privacy column to public.profiles so setPrivacy() in
-- the frontend can actually persist the user's choice.
-- Existing rows default to 'public'.
-- ============================================================

ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS privacy TEXT NOT NULL DEFAULT 'public'
  CHECK (privacy IN ('public', 'private'));
