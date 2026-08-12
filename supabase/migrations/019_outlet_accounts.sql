-- ============================================================
-- 019_outlet_accounts.sql
--
-- 1. Adds account_type column to profiles so the UI can label
--    outlet accounts distinctly from real users.
-- 2. Creates auth.users entries for BBC News and The Guardian
--    (these accounts cannot log in — empty password, no KYC).
--    The handle_new_user trigger fires automatically and creates
--    matching profiles rows.
-- 3. Patches those profile rows with outlet-specific values.
--
-- Fixed UUIDs (also hard-coded in api/fetch-news.js and index.html):
--   BBC News:     a0000000-0000-0000-0000-000000000001
--   The Guardian: a0000000-0000-0000-0000-000000000002
--
-- ⚠️ Run in the Supabase SQL editor.
-- ⚠️ If the INSERT into auth.users fails with a "column does not
--    exist" error, your Supabase version may require an
--    instance_id column — add it as a constant UUID value
--    '00000000-0000-0000-0000-000000000000' to both rows.
-- ============================================================

-- ── Step 1: Add account_type column ─────────────────────────
ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS account_type TEXT NOT NULL DEFAULT 'person'
  CHECK (account_type IN ('person', 'outlet'));

-- ── Step 2: Create auth.users entries ───────────────────────
-- These rows satisfy the FK constraint on profiles.id.
-- Outlet accounts have no usable password and cannot sign in.
INSERT INTO auth.users (
  id,
  aud,
  role,
  email,
  encrypted_password,
  email_confirmed_at,
  raw_app_meta_data,
  raw_user_meta_data,
  created_at,
  updated_at
) VALUES (
  'a0000000-0000-0000-0000-000000000001',
  'authenticated',
  'authenticated',
  'bbc-news@hatch-outlet.internal',
  '',
  now(),
  '{"provider":"email","providers":["email"]}',
  '{}',
  now(),
  now()
), (
  'a0000000-0000-0000-0000-000000000002',
  'authenticated',
  'authenticated',
  'guardian@hatch-outlet.internal',
  '',
  now(),
  '{"provider":"email","providers":["email"]}',
  '{}',
  now(),
  now()
)
ON CONFLICT (id) DO NOTHING;

-- ── Step 3: Patch the auto-created profiles ──────────────────
-- The handle_new_user trigger created basic profile rows when
-- auth.users was inserted above. Patch them now with full details.
UPDATE public.profiles SET
  name         = 'BBC News',
  bio          = 'Breaking news, analysis and insight from the UK and around the world. Official BBC News account on Hatch.',
  verified     = true,
  privacy      = 'public',
  account_type = 'outlet'
WHERE id = 'a0000000-0000-0000-0000-000000000001';

UPDATE public.profiles SET
  name         = 'The Guardian',
  bio          = 'Independent journalism. Latest news, opinion and analysis from The Guardian.',
  verified     = true,
  privacy      = 'public',
  account_type = 'outlet'
WHERE id = 'a0000000-0000-0000-0000-000000000002';
