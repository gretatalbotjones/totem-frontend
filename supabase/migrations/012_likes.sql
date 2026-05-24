-- ============================================================
-- 012_likes.sql
--
-- Documentation migration — likes table was applied manually
-- to the live database. This file records the schema so it is
-- version-controlled alongside the rest of the migrations.
--
-- Safe to re-run: all statements use IF NOT EXISTS guards.
-- ============================================================

CREATE TABLE IF NOT EXISTS public.likes (
  post_id    UUID        NOT NULL REFERENCES public.posts(id) ON DELETE CASCADE,
  user_id    UUID        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (post_id, user_id)
);

ALTER TABLE public.likes ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'likes'
      AND policyname = 'likes: public read'
  ) THEN
    CREATE POLICY "likes: public read"
      ON public.likes FOR SELECT
      USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'likes'
      AND policyname = 'likes: owner insert'
  ) THEN
    CREATE POLICY "likes: owner insert"
      ON public.likes FOR INSERT
      WITH CHECK (auth.uid() = user_id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'likes'
      AND policyname = 'likes: owner delete'
  ) THEN
    CREATE POLICY "likes: owner delete"
      ON public.likes FOR DELETE
      USING (auth.uid() = user_id);
  END IF;
END $$;
