-- ============================================================
-- 013_saved_posts.sql
--
-- Documentation migration — saved_posts table was applied
-- manually to the live database. This file records the schema
-- so it is version-controlled alongside the rest of the
-- migrations.
--
-- Note: timestamp column is saved_at (not created_at).
--
-- Safe to re-run: all statements use IF NOT EXISTS guards.
-- ============================================================

CREATE TABLE IF NOT EXISTS public.saved_posts (
  user_id  UUID        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  post_id  UUID        NOT NULL REFERENCES public.posts(id) ON DELETE CASCADE,
  saved_at TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (user_id, post_id)
);

ALTER TABLE public.saved_posts ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'saved_posts'
      AND policyname = 'saved_posts: owner all'
  ) THEN
    CREATE POLICY "saved_posts: owner all"
      ON public.saved_posts FOR ALL
      USING (auth.uid() = user_id);
  END IF;
END $$;
