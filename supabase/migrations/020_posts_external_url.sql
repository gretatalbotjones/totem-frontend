-- ============================================================
-- 020_posts_external_url.sql
--
-- Adds external_url column to posts for storing the canonical
-- link back to a news article's original source. Used by the
-- api/fetch-news.js serverless poller to store article URLs
-- and to deduplicate: a post is only inserted if no existing
-- row has the same external_url.
--
-- Displayed in the UI as a "Read full article ↗" link on
-- news post cards and in the article modal.
--
-- ⚠️ Run in the Supabase SQL editor.
-- ============================================================

ALTER TABLE public.posts
  ADD COLUMN IF NOT EXISTS external_url TEXT;
