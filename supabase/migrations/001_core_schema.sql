-- ============================================================
-- 001_core_schema.sql
-- Core schema for Hatch — profiles, posts, follows
-- Run this in the Supabase SQL editor or via the CLI:
--   supabase db push
-- ============================================================


-- ── PROFILES ────────────────────────────────────────────────

create table if not exists public.profiles (
  id          uuid primary key references auth.users (id) on delete cascade,
  username    text unique,
  full_name   text,
  avatar_url  text,
  created_at  timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- Anyone can read any profile (needed for search, viewing pages)
create policy "profiles: public read"
  on public.profiles for select
  using (true);

-- Users can only update their own profile
create policy "profiles: owner update"
  on public.profiles for update
  using (auth.uid() = id);

-- The trigger (below) handles insert — no direct insert policy needed


-- ── POSTS ───────────────────────────────────────────────────

create table if not exists public.posts (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references public.profiles (id) on delete cascade,
  content     text,
  image_url   text,
  visibility  text not null default 'friends'
                check (visibility in ('friends', 'public')),
  created_at  timestamptz not null default now()
);

alter table public.posts enable row level security;

-- Public posts are readable by anyone
create policy "posts: public read"
  on public.posts for select
  using (visibility = 'public');

-- Friends posts are readable only by followers
create policy "posts: friends read"
  on public.posts for select
  using (
    visibility = 'friends'
    and (
      auth.uid() = user_id
      or exists (
        select 1 from public.follows
        where follower_id = auth.uid()
          and following_id = posts.user_id
      )
    )
  );

-- Users can insert their own posts
create policy "posts: owner insert"
  on public.posts for insert
  with check (auth.uid() = user_id);

-- Users can update their own posts
create policy "posts: owner update"
  on public.posts for update
  using (auth.uid() = user_id);

-- Users can delete their own posts
create policy "posts: owner delete"
  on public.posts for delete
  using (auth.uid() = user_id);


-- ── FOLLOWS ─────────────────────────────────────────────────

create table if not exists public.follows (
  follower_id   uuid not null references public.profiles (id) on delete cascade,
  following_id  uuid not null references public.profiles (id) on delete cascade,
  created_at    timestamptz not null default now(),
  primary key (follower_id, following_id),
  -- Prevent self-follows
  constraint no_self_follow check (follower_id <> following_id)
);

alter table public.follows enable row level security;

-- Follows are readable by anyone (required to evaluate post visibility)
create policy "follows: public read"
  on public.follows for select
  using (true);

-- Users can follow others (insert their own follower_id rows)
create policy "follows: owner insert"
  on public.follows for insert
  with check (auth.uid() = follower_id);

-- Users can unfollow (delete their own follower_id rows)
create policy "follows: owner delete"
  on public.follows for delete
  using (auth.uid() = follower_id);


-- ── AUTO-CREATE PROFILE ON SIGNUP ───────────────────────────
-- Fires after a new row is inserted into auth.users.
-- Pulls name and avatar from the user_metadata set during signUp().

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, avatar_url)
  values (
    new.id,
    new.raw_user_meta_data ->> 'name',
    new.raw_user_meta_data ->> 'avatar_url'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

-- Drop the trigger first so re-running this file is safe
drop trigger if exists on_auth_user_created on auth.users;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();
