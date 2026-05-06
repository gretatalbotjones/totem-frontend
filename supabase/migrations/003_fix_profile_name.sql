-- ============================================================
-- 003_fix_profile_name.sql
--
-- Problem: 001_core_schema.sql created profiles with a `full_name`
-- column and the handle_new_user trigger writes to `full_name`.
-- 002_mvp_features.sql added a separate `name` column but the
-- trigger was never updated, so every real user has name = NULL.
-- The JS search queries ilike on `name`, so it always returns
-- nothing.
--
-- Fix:
--   1. Backfill name from full_name for all existing rows.
--   2. Replace the trigger function so new sign-ups write to name.
--   3. Confirm the profiles SELECT policy covers authenticated users.
-- ============================================================

-- 1. Backfill existing rows
update public.profiles
set    name = full_name
where  name is null
  and  full_name is not null;

-- 2. Update trigger to write name (as well as full_name for compat)
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, name, full_name, avatar_url)
  values (
    new.id,
    new.raw_user_meta_data ->> 'name',
    new.raw_user_meta_data ->> 'name',
    new.raw_user_meta_data ->> 'avatar_url'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

-- 3. Ensure the public SELECT policy exists (idempotent)
drop policy if exists "profiles: public read" on public.profiles;

create policy "profiles: public read"
  on public.profiles for select
  using (true);
