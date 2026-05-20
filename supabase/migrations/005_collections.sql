-- ============================================================
-- 005_collections.sql
--
-- Adds collections and collection_items tables so users can
-- persist named collections of posts to Supabase.
-- ============================================================

CREATE TABLE IF NOT EXISTS public.collections (
  id          uuid        DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id     uuid        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  name        TEXT        NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.collection_items (
  id             uuid        DEFAULT gen_random_uuid() PRIMARY KEY,
  collection_id  uuid        NOT NULL REFERENCES public.collections(id) ON DELETE CASCADE,
  post_id        uuid        NOT NULL REFERENCES public.posts(id) ON DELETE CASCADE,
  created_at     TIMESTAMPTZ DEFAULT now(),
  UNIQUE(collection_id, post_id)
);

ALTER TABLE public.collections      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.collection_items ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users manage own collections"
  ON public.collections FOR ALL
  USING (user_id = auth.uid());

CREATE POLICY "Users manage own collection items"
  ON public.collection_items FOR ALL
  USING (
    collection_id IN (
      SELECT id FROM public.collections WHERE user_id = auth.uid()
    )
  );
