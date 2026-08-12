# CLAUDE.md — Hatch Project Instructions

Read this file at the start of every session before touching any code.

---

## What this project is

**Hatch** is a privacy-first social media platform. It is a Social Utility, not a hypergrowth consumer social app. Core proposition: user-controlled, chronological, algorithm-free social networking with verified identity.

Tagline: *"Your content. Your rules."*

Key differentiators:
- No data selling, no behavioural advertising
- KYC-verified accounts (video verification at signup)
- Algorithm dial (chronological ↔ suggested)
- Trusted Circles (named groups with per-post audience picker)
- Three feed surfaces: Personal, Pulse (hyper-local), News (verified outlets only)
- QR ID card (Phase 2+)

Target demographic: 25–40, UK-first, privacy-forward.

---

## Current tech stack

| Layer | Tech |
|---|---|
| Frontend | Single HTML file (`index.html`) — vanilla JS, inline CSS |
| Backend | Supabase (auth + database + storage) |
| Hosting | Vercel — https://totem-frontend-five.vercel.app/ |
| Future migration | Next.js + Supabase (planned post-MVP) |

**The single HTML file is a prototype. It will be migrated to Next.js after Phase 1 MVP is complete. Do not restructure it into multiple files — make targeted edits only.**

---

## Supabase project

- Project URL: `https://ocztxpmmbopcbtshetts.supabase.co`
- Publishable key: `sb_publishable_QcqD9p8Wk8zHRV-dsSQ4Xw_bVkdC2fy`

### Tables (confirmed in schema)

| Table | Key columns |
|---|---|
| `profiles` | id, name, bio, avatar_url, verified, privacy, created_at |
| `posts` | id, user_id, caption, image_url, feed_type, visibility, created_at |
| `follows` | follower_id, following_id |
| `events` | id, user_id, title, description, location, starts_at, ends_at, visibility, cover_image_url |
| `event_invites` | event_id, invitee_id, rsvp |

### Storage buckets
- `avatars` — profile photos
- `posts` — post images

### Migrations applied
- `001_core_schema.sql`
- `002_mvp_features.sql`
- `003_fix_profile_name.sql` — backfills name, fixes trigger, adds public SELECT policy
- `004_add_privacy_column.sql` — adds privacy TEXT NOT NULL DEFAULT 'public' to profiles ⚠️ run in Supabase SQL editor
- `005_collections.sql` — creates collections and collection_items tables with RLS ⚠️ run in Supabase SQL editor
- `006_invite_codes.sql` — creates invite_codes table with RLS + seeds 10 test codes ⚠️ run in Supabase SQL editor
- `007_diary_private_rls.sql` — RLS policy restricting diary post reads to owner only ⚠️ run in Supabase SQL editor
- `008_follow_requests.sql` — follow_requests table with RLS (requester + target policies) ⚠️ run in Supabase SQL editor
- `009_notifications.sql` — notifications table with RLS ⚠️ run in Supabase SQL editor
- `010_follows_approve_policy.sql` — extends follows INSERT policy to allow `following_id = auth.uid()` (needed for approve flow) ⚠️ run in Supabase SQL editor
- `016_fix_posts_visibility_check.sql` — drops and recreates posts_visibility_check to include 'private' (needed for diary posts) ⚠️ run in Supabase SQL editor
- `017_circles.sql` — creates circles and circle_members tables with RLS for Trusted Circles feature
- `018_circle_member_lookup.sql` — SECURITY DEFINER RPC `get_circle_owners_for_member(uuid)` so viewers can check which posters include them in a circle (feeds P2-6 audience filter) ⚠️ run in Supabase SQL editor
- `019_outlet_accounts.sql` — adds `account_type` column to profiles; creates BBC News (UUID `a0000000-0000-0000-0000-000000000001`) and The Guardian (UUID `a0000000-0000-0000-0000-000000000002`) as outlet accounts in auth.users + profiles ⚠️ run in Supabase SQL editor
- `020_posts_external_url.sql` — adds `external_url TEXT` column to posts for storing canonical article links ⚠️ run in Supabase SQL editor

### Outlet accounts (news)
- BBC News profile id: `a0000000-0000-0000-0000-000000000001`
- The Guardian profile id: `a0000000-0000-0000-0000-000000000002`
- Both are `account_type = 'outlet'`, `verified = true`, `privacy = 'public'`
- News articles are inserted by `api/fetch-news.js` (Vercel serverless, runs hourly via vercel.json cron)
- Required Vercel env vars: `SUPABASE_URL`, `SUPABASE_SERVICE_KEY` (service_role key), `CRON_SECRET`

---

## Demo account

- Email: `greta.talbot.jones@gmail.com`
- Name: `Greta Talbot-Jones`
- The `isDemoAccount` flag gates hardcoded demo data (`_DEMO_POSTS`, `_DEMO_CONTACTS`, `_DEMO_EVENTS`)
- **Real users must never see demo data.** The check is `email === DEMO_ACCOUNT_EMAIL`

---

## Code conventions

- All Supabase writes must be guarded: `if (supabaseClient && currentUser.id && currentUser.name !== DEMO_ACCOUNT_NAME)`
- Always use `console.warn('[Hatch] ...')` for non-fatal errors
- Use `showToast('message')` for user-facing feedback
- Never hardcode user IDs, emails, or profile data outside the demo account block
- Preserve all existing IDs and function names — JS is tightly coupled to HTML IDs
- When adding new Supabase columns, always include an `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` migration
- New migrations go in `supabase/migrations/` with sequential numbering

## What NOT to do

- Do not restructure the HTML file into multiple files
- Do not rewrite existing functions — extend or patch them
- Do not add new npm dependencies without flagging it
- Do not show demo data to real users
- Do not make follow/unfollow changes without preserving the `fpCurrentProfileId` reference
- Do not change z-index values on modals without checking the full z-index stack:
  - `.tab-bar`: 355
  - `#friendProfileModal`: 350
  - `#fpSubNav`: 360
  - Other modals (sendPostModal, article-modal-overlay): 400+

---

## Phase 1 MVP scope

Features that must ship before real user testing:

1. Profile + posting (photo, video, text)
2. Follow graph with follow request flow (request → approve/decline)
3. Algorithm dial (chronological ↔ suggested)
4. Trusted Circles (named groups + per-post audience picker)
5. KYC video verification (video uploaded to Supabase Storage)
6. Collections (persisted to Supabase)
7. Invite code system (gate on signup)
8. Home feed (followed users only, from Supabase, no demo data bleed)
9. Auth (signup, login, logout, password reset)
10. Avatar upload prompt post signup

Features deferred to Phase 2+:
- Diary (ephemeral 24-hour posts)
- Memories archive (shareable)
- DMs
- News/Pulse feed surfaces
- QR ID card
- Feed Switch (Instagram import)
- Feed+ subscriptions

---

## Backup protocol

**Before starting any session that involves code changes:**
```bash
cp index.html backups/index_backup_$(date +%Y%m%d_%H%M).html
```

**After completing a working feature:**
```bash
cp index.html backups/index_backup_$(date +%Y%m%d_%H%M).html
```

Backups live in the `backups/` folder. Do not delete backups. Do not commit backups to git — add `backups/` to `.gitignore`.
