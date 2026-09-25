# Architecture

## Current architecture

**Single HTML file prototype.** Everything — CSS, HTML, JavaScript — lives in `index.html` (~10,800 lines).

```
Browser
└── index.html
      ├── CSS (~2,200 lines inline)
      ├── HTML (~1,400 lines) — 5 tab-pages + modals
      └── JavaScript (~7,200 lines)
            ├── ~40 global variables (currentUser, posts, events, contacts…)
            ├── Supabase JS SDK (CDN: cdn.jsdelivr.net, pinned @2.105.3)
            ├── Direct Supabase calls throughout (no data layer abstraction)
            └── DOM manipulation via getElementById everywhere

Supabase (backend-as-a-service)
├── Auth — email/password, OTP, session management
├── PostgreSQL — all application data (20 migrations applied)
├── Storage — avatars bucket, posts bucket
└── Realtime — feed new-post subscription channel

Vercel (hosting)
├── index.html — static file, auto-deploys from GitHub main branch
└── api/fetch-news.js — CommonJS serverless function (RSS ingestion)

GitHub
└── gretatalbotjones/totem-frontend — source of truth, triggers Vercel deploy
```

### Known architectural problems

1. **Single-file fragility** — one JS parse error crashes the entire app (happened twice in production). No isolation between features.
2. **Global state everywhere** — ~40 module-level variables with no encapsulation. `currentUser`, `posts`, `events`, `groupDefs`, `contacts` are all mutable globals.
3. **DOM as state** — `getElementById` used to both read and write state (e.g. reading `followerCount.textContent` as a number). No single source of truth.
4. **Inline onclick handlers** — `onclick="..."` strings in HTML make refactoring dangerous and prevent proper event delegation.
5. **Demo/real interleaved** — `_DEMO_POSTS`, `_DEMO_CONTACTS`, `_DEMO_EVENTS` arrays guarded by `isDemoAccount` scattered throughout. Risk of demo data leaking to real users.
6. **No types** — all Supabase responses are untyped. Field name typos cause silent bugs (e.g. `user_id` vs `userId`).
7. **Scale ceiling** — at 10,800 lines, further meaningful features are high-risk to add.

---

## Target architecture

Next.js 14 (App Router) + TypeScript + Tailwind CSS + Supabase (unchanged) + Zustand.

See `docs/migration-plan.md` for the phased approach.

```
Next.js app (new repo: hatch-web)
├── app/
│   ├── (auth)/              — login, register, verify — no nav bar
│   └── (app)/               — all authenticated routes — with nav bar
│       ├── layout.tsx        — TopNav + BottomNav shell
│       ├── feed/page.tsx
│       ├── events/page.tsx
│       ├── notifications/page.tsx
│       ├── messages/page.tsx
│       └── profile/[id]/page.tsx
├── components/              — reusable React components
├── lib/supabase/            — typed Supabase client (browser + server)
├── lib/hooks/               — useFeed, useUser, useNotifications, useCircles
├── store/useAppStore.ts     — Zustand (replaces global JS variables)
└── supabase/migrations/     — all 20 existing migrations carry forward

Supabase — unchanged (same project, same URL, same keys, same schema)
Vercel — same project, connect new repo
```

**Key tech choices:** TypeScript (Supabase-generated types), Tailwind (design tokens already defined), Zustand (replaces ~40 globals), `@supabase/ssr` (server-side sessions), Onfido (real KYC), Next.js Image (auto-optimisation).

---

## Database design

All 20 migrations are applied. Schema is stable.

```sql
profiles        (id uuid PK → auth.users, name, bio, avatar_url, verified bool,
                 privacy text, account_type text, created_at)

posts           (id uuid PK, user_id → profiles, caption, image_url,
                 feed_type text, visibility text, external_url, created_at)

follows         (follower_id → profiles, following_id → profiles, created_at)
                 UNIQUE(follower_id, following_id), no self-follow constraint

follow_requests (id, requester_id → profiles, target_id → profiles,
                 status text [pending/approved/declined], created_at)

events          (id, user_id → profiles, title, description, location,
                 starts_at, ends_at, visibility [public/private/invite])

event_invites   (event_id → events, invitee_id → profiles,
                 rsvp [pending/going/maybe/declined])   PK(event_id, invitee_id)

collections     (id, user_id → profiles, name, created_at)
collection_items(id, collection_id → collections, post_id → posts)

invite_codes    (id, code text UNIQUE, used_by → profiles, used_at)

notifications   (id, user_id → profiles, type text, actor_id → profiles,
                 entity_id, text, read bool, created_at)

likes           (id, post_id → posts, user_id → profiles, created_at)
saved_posts     (id, post_id → posts, user_id → profiles, saved_at)
comments        (id, post_id → posts, user_id → profiles, text, created_at)

circles         (id, user_id → profiles, name, created_at)
circle_members  (id, circle_id → circles, member_id → profiles, created_at)
                 UNIQUE(circle_id, member_id)
```

All tables have RLS enabled. Key RLS patterns:
- `profiles`: public SELECT (true); owner UPDATE
- `posts`: public read for `visibility='public'`; follower read for `visibility='friends'`; owner INSERT/UPDATE/DELETE
- `follows`: public SELECT; owner INSERT/DELETE
- `notifications`: owner SELECT/UPDATE; any authenticated INSERT (needed for cross-user notifications)

### Special database objects

```sql
-- Migration 018: SECURITY DEFINER RPC
-- Needed because circle_members RLS only allows circle owner to read rows.
-- Used by loadFeedFromSupabase() to filter friends-only posts.
get_circle_owners_for_member(member_uuid UUID) → TABLE(owner_id UUID)
```

### Outlet accounts (special profiles)
```
BBC News:     id = 'a0000000-0000-0000-0000-000000000001'
The Guardian: id = 'a0000000-0000-0000-0000-000000000002'
account_type = 'outlet', verified = true, privacy = 'public'
Posts inserted by api/fetch-news.js using service role key
```

---

## Authentication

**Current (prototype):** Supabase Auth via CDN JS SDK. `onAuthStateChange` listener manages session. PKCE flow for password reset.

**Session flow:**
1. User signs in → Supabase sets session cookie / localStorage
2. `onAuthStateChange` fires `SIGNED_IN` → `enterApp()` called
3. `enterApp()` loads profile, follows, circles, notifications in parallel
4. `SIGNED_OUT` event → `showAuthScreen()`

**Known auth issues:** Password reset requires detecting the URL hash on page load (PKCE code in URL). Current implementation uses `supabase.auth.exchangeCodeForSession()` on load.

**Target (Next.js):** `@supabase/ssr` package. Middleware checks session cookie. Server-side session available on first render. No `onAuthStateChange` listener needed.

---

## Deployment

**Live URL:** https://totem-frontend-five.vercel.app/

**Deploy process:** Push to `main` branch on GitHub → Vercel auto-deploys (typically <60 seconds).

**Environment variables (set in Vercel project settings):**
```
SUPABASE_URL         = https://ocztxpmmbopcbtshetts.supabase.co
SUPABASE_SERVICE_KEY = [service_role key — in Vercel, NOT in git]
CRON_SECRET          = hatch-cron-2026-secret-xyz
```

**News ingestion (manual trigger):**
```bash
curl -H "Authorization: Bearer hatch-cron-2026-secret-xyz" \
  https://totem-frontend-five.vercel.app/api/fetch-news
```
Returns `{"inserted": N, "errors": [], "feeds": 5}`. Requires Vercel Pro for auto-cron; currently manual.

**Test suite:**
```bash
node tests/supabase_test_suite.js
# Expected: 39 tests, 36 pass, 0 fail, 3 skip
```

---

## Important decisions

| Decision | What was chosen | Why |
|---|---|---|
| Single HTML file | Keep as prototype | Migration is planned but not started — see migration-plan.md |
| Supabase over Firebase | Supabase | PostgreSQL, open source, self-hostable, RLS, better privacy story |
| No npm dependencies (frontend) | CDN-loaded Supabase JS | Prototype simplicity — Next.js migration will use proper npm |
| Outlet accounts as Supabase profiles | Real profiles with fixed UUIDs | FK integrity, queryable like any user, followable via standard flow |
| SECURITY DEFINER RPC for circles | `get_circle_owners_for_member()` | Circle member RLS only allows owner reads; viewer needs to know if they're in someone's circle — circular RLS would cause infinite recursion |
| RSS ingestion as serverless function | `api/fetch-news.js` | No CORS on server-side, no npm XML parser needed (regex extraction), free on Vercel Hobby |
| Audience filtering client-side | Filter after fetch, not in query | PostgREST nested AND/OR syntax is unreliable; client-side filter on 60 posts is negligible cost |
| `commonjs` module type | `"type": "commonjs"` in package.json | Vercel serverless functions need CommonJS; ESM `export default` caused 404s |
| KYC deferred to P3 | Fake UI stub | Real implementation needs Onfido account + webhook endpoint — significant scope |
