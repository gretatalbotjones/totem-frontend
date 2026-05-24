-- ============================================================
-- 016_fix_posts_visibility_check.sql
--
-- The original CHECK constraint on posts.visibility only
-- allowed ('friends', 'public'). Diary entries write
-- visibility = 'private', which violated the constraint and
-- caused diary post inserts to fail silently for real users.
--
-- Drops the old constraint and replaces it with one that
-- includes 'private'.
--
-- ⚠️ Run in the Supabase SQL editor.
-- ============================================================

ALTER TABLE public.posts
  DROP CONSTRAINT IF EXISTS posts_visibility_check;

ALTER TABLE public.posts
  ADD CONSTRAINT posts_visibility_check
  CHECK (visibility IN ('friends', 'public', 'private'));
