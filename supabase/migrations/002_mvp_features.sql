-- ============================================================
-- 002_mvp_features.sql
-- Adds profile name/bio, post feed_type, events, event_invites
-- ============================================================

-- ── PROFILES: add name and bio ───────────────────────────────
alter table public.profiles add column if not exists name text;
alter table public.profiles add column if not exists bio  text;

-- ── POSTS: add feed_type ────────────────────────────────────
alter table public.posts add column if not exists feed_type text not null default 'personal';

-- ── EVENTS ──────────────────────────────────────────────────
create table if not exists public.events (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references public.profiles (id) on delete cascade,
  title           text not null,
  description     text,
  location        text,
  starts_at       timestamptz,
  ends_at         timestamptz,
  visibility      text not null default 'public'
                    check (visibility in ('public', 'private', 'invite')),
  cover_image_url text,
  created_at      timestamptz not null default now()
);

alter table public.events enable row level security;

drop policy if exists "events: public read"    on public.events;
drop policy if exists "events: followers read" on public.events;
drop policy if exists "events: invitees read"  on public.events;
drop policy if exists "events: owner insert"   on public.events;
drop policy if exists "events: owner update"   on public.events;
drop policy if exists "events: owner delete"   on public.events;

create policy "events: public read"
  on public.events for select
  using (visibility = 'public');

create policy "events: followers read"
  on public.events for select
  using (
    visibility = 'private'
    and (
      auth.uid() = user_id
      or exists (
        select 1 from public.follows
        where follower_id = auth.uid() and following_id = events.user_id
      )
    )
  );

create policy "events: invitees read"
  on public.events for select
  using (
    visibility = 'invite'
    and (
      auth.uid() = user_id
      or exists (
        select 1 from public.event_invites
        where event_id = events.id and invitee_id = auth.uid()
      )
    )
  );

create policy "events: owner insert"
  on public.events for insert
  with check (auth.uid() = user_id);

create policy "events: owner update"
  on public.events for update
  using (auth.uid() = user_id);

create policy "events: owner delete"
  on public.events for delete
  using (auth.uid() = user_id);

-- ── EVENT INVITES ────────────────────────────────────────────
create table if not exists public.event_invites (
  event_id    uuid not null references public.events (id) on delete cascade,
  invitee_id  uuid not null references public.profiles (id) on delete cascade,
  rsvp        text not null default 'pending'
                check (rsvp in ('pending', 'going', 'maybe', 'declined')),
  created_at  timestamptz not null default now(),
  primary key (event_id, invitee_id)
);

alter table public.event_invites enable row level security;

drop policy if exists "event_invites: read"           on public.event_invites;
drop policy if exists "event_invites: owner insert"   on public.event_invites;
drop policy if exists "event_invites: invitee update" on public.event_invites;

-- Only invitees can read their own invite rows.
-- (Referencing events here would create mutual recursion with "events: invitees read".)
create policy "event_invites: read"
  on public.event_invites for select
  using (invitee_id = auth.uid());

create policy "event_invites: owner insert"
  on public.event_invites for insert
  with check (
    exists (
      select 1 from public.events
      where id = event_invites.event_id and user_id = auth.uid()
    )
  );

create policy "event_invites: invitee update"
  on public.event_invites for update
  using (invitee_id = auth.uid());
