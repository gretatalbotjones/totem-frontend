-- 003_fix_profile_name.sql (corrected for actual schema)

-- 1. Update trigger to write to name column
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, name, avatar_url)
  values (
    new.id,
    new.raw_user_meta_data ->> 'name',
    new.raw_user_meta_data ->> 'avatar_url'
  )
  on conflict (id) do update
    set name = excluded.name,
        avatar_url = excluded.avatar_url;
  return new;
end;
$$;

-- 2. Ensure public SELECT policy exists
drop policy if exists "profiles: public read" on public.profiles;

create policy "profiles: public read"
  on public.profiles for select
  using (true);