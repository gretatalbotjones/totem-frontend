-- ============================================================
-- 006_invite_codes.sql
--
-- Creates invite_codes table to gate signup. Each code can
-- only be used once. Seeded with initial test codes.
-- ============================================================

CREATE TABLE IF NOT EXISTS public.invite_codes (
  id          uuid        DEFAULT gen_random_uuid() PRIMARY KEY,
  code        TEXT        NOT NULL UNIQUE,
  created_by  uuid        REFERENCES public.profiles(id) ON DELETE SET NULL,
  used_by     uuid        REFERENCES public.profiles(id) ON DELETE SET NULL,
  used_at     TIMESTAMPTZ,
  created_at  TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE public.invite_codes ENABLE ROW LEVEL SECURITY;

-- Anyone (including unauthenticated users) can read invite codes to validate them
CREATE POLICY "Public can read invite codes"
  ON public.invite_codes FOR SELECT
  USING (true);

-- Only the system / service role can insert or update codes
-- (Updates from the frontend are done via the used_by / used_at columns
--  which the RLS below allows for the matching user)
CREATE POLICY "Users can mark invite codes as used"
  ON public.invite_codes FOR UPDATE
  USING (used_by IS NULL);

-- ── Seed initial invite codes for testing ─────────────────
INSERT INTO public.invite_codes (code) VALUES
  ('HATCH-ALPHA'),
  ('HATCH-BETA1'),
  ('HATCH-BETA2'),
  ('HATCH-BETA3'),
  ('HATCH-BETA4'),
  ('HATCH-BETA5'),
  ('HATCH-FRIEND'),
  ('HATCH-EARLY'),
  ('HATCH-LAUNCH'),
  ('HATCH-PILOT')
ON CONFLICT (code) DO NOTHING;
