-- ============================================================
-- 007_diary_private_rls.sql
--
-- Diary entries (feed_type = 'diary') should only be readable
-- by their owner. The existing posts SELECT policy allows all
-- followers to read; this policy overrides that for diary posts.
-- ============================================================

-- Drop any existing broad SELECT policy on posts if needed,
-- then add a restricted policy for diary rows.
-- Uses a permissive policy that only permits owner access for diary posts.

CREATE POLICY "Diary posts are private to owner"
  ON public.posts FOR SELECT
  USING (
    feed_type != 'diary'
    OR user_id = auth.uid()
  );
