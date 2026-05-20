-- ============================================================
-- 010_follows_approve_policy.sql
--
-- Extends the follows INSERT policy so that a user approving
-- a follow request can insert the row on behalf of the requester.
-- Previously only follower_id = auth.uid() was permitted, which
-- blocks the approve flow where the target (following_id) does
-- the insert.
-- ============================================================

DROP POLICY IF EXISTS "follows: owner insert" ON public.follows;

CREATE POLICY "follows: owner insert"
  ON public.follows FOR INSERT
  WITH CHECK (auth.uid() = follower_id OR auth.uid() = following_id);
