-- ============================================================
-- 011_comments.sql
--
-- Documentation migration — comments table was applied manually
-- to the live database. This file records the schema so it is
-- version-controlled alongside the rest of the migrations.
--
-- Safe to re-run: all statements use IF NOT EXISTS guards.
-- ============================================================

CREATE TABLE IF NOT EXISTS public.comments (
  id         UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  post_id    UUID        NOT NULL REFERENCES public.posts(id) ON DELETE CASCADE,
  user_id    UUID        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  content    TEXT        NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE public.comments ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'comments'
      AND policyname = 'comments: public read'
  ) THEN
    CREATE POLICY "comments: public read"
      ON public.comments FOR SELECT
      USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'comments'
      AND policyname = 'comments: owner insert'
  ) THEN
    CREATE POLICY "comments: owner insert"
      ON public.comments FOR INSERT
      WITH CHECK (auth.uid() = user_id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'comments'
      AND policyname = 'comments: owner delete'
  ) THEN
    CREATE POLICY "comments: owner delete"
      ON public.comments FOR DELETE
      USING (auth.uid() = user_id);
  END IF;
END $$;
