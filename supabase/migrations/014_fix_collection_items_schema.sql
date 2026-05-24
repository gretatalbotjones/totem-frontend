-- ============================================================
-- 014_fix_collection_items_schema.sql
--
-- Documentation migration — the live collection_items table
-- differs from what migration 005_collections.sql specified.
--
-- Live schema (confirmed via test suite):
--   collection_id  UUID  NOT NULL  (FK → collections.id)
--   post_id        UUID  NOT NULL  (FK → posts.id)
--   added_at       TIMESTAMPTZ
--   PRIMARY KEY (collection_id, post_id)   ← composite, no id column
--
-- 005_collections.sql specified:
--   id UUID PRIMARY KEY  ← does NOT exist in the live DB
--   created_at           ← live DB uses added_at instead
--
-- This migration is a no-op against the live DB (the table
-- already exists in its current form). It documents the actual
-- schema so future migrations and the test suite have an
-- accurate reference.
--
-- Safe to re-run: CREATE TABLE IF NOT EXISTS is a no-op when
-- the table already exists.
-- ============================================================

-- No DDL changes needed — table already exists in the live DB.
-- This file serves as a schema record only.

-- Actual live schema for reference:
--
-- CREATE TABLE public.collection_items (
--   collection_id  UUID        NOT NULL REFERENCES public.collections(id) ON DELETE CASCADE,
--   post_id        UUID        NOT NULL REFERENCES public.posts(id) ON DELETE CASCADE,
--   added_at       TIMESTAMPTZ DEFAULT now(),
--   PRIMARY KEY (collection_id, post_id)
-- );

SELECT 1; -- placeholder so this file is valid SQL
