-- ============================================================
-- 017_circles.sql
--
-- Creates Trusted Circles (circles + circle_members) tables.
-- Circles are named groups used as the audience when composing
-- posts. The audience picker in the post modal reads from this
-- table so circles persist across sessions.
--
-- Default circles (Family, Close Friends) are seeded for new
-- users in finishRegistration() in index.html — not here.
--
-- ⚠️ Run in the Supabase SQL editor.
-- ============================================================

CREATE TABLE IF NOT EXISTS public.circles (
  id         UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id    UUID        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  name       TEXT        NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.circle_members (
  id         UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  circle_id  UUID        NOT NULL REFERENCES public.circles(id) ON DELETE CASCADE,
  member_id  UUID        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE (circle_id, member_id)
);

ALTER TABLE public.circles        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.circle_members ENABLE ROW LEVEL SECURITY;

-- Circle owner has full control over their circles
DROP POLICY IF EXISTS "circles: owner all" ON public.circles;
CREATE POLICY "circles: owner all"
  ON public.circles FOR ALL
  USING (user_id = auth.uid());

-- Circle members table: only the circle owner can manage entries
DROP POLICY IF EXISTS "circle_members: owner all" ON public.circle_members;
CREATE POLICY "circle_members: owner all"
  ON public.circle_members FOR ALL
  USING (
    circle_id IN (
      SELECT id FROM public.circles WHERE user_id = auth.uid()
    )
  );
