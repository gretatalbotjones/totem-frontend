# Hatch — Architecture

## Current architecture (prototype)

```
Browser
  └── index.html (single file, ~10,800 lines)
        ├── CSS (~2,200 lines inline)
        ├── HTML (~1,400 lines)
        └── JavaScript (~7,200 lines)
              ├── Global state (JS variables: currentUser, posts, events, contacts…)
              ├── Auth (Supabase JS SDK, CDN-loaded)
              ├── Data fetching (direct Supabase calls, no abstraction layer)
              ├── DOM manipulation (getElementById everywhere)
              └── Business logic (intermixed with rendering)

Supabase (Backend as a Service)
  ├── Auth (email/password, OTP)
  ├── PostgreSQL (profiles, posts, follows, events, notifications…)
  ├── Storage (avatars bucket, posts bucket)
  └── Realtime (feed new-post subscription)

Vercel (Hosting)
  ├── index.html (static file serving)
  └── api/fetch-news.js (serverless function — RSS ingestion)
```

### Database schema

```
profiles        (id, name, bio, avatar_url, verified, privacy, account_type, created_at)
posts           (id, user_id, caption, image_url, feed_type, visibility, external_url, created_at)
follows         (follower_id, following_id, created_at)
follow_requests (id, requester_id, target_id, status, created_at)
events          (id, user_id, title, description, location, starts_at, ends_at, visibility, cover_image_url)
event_invites   (event_id, invitee_id, rsvp)
collections     (id, user_id, name, created_at)
collection_items(id, collection_id, post_id, created_at)
invite_codes    (id, code, used_by, used_at, created_at)
notifications   (id, user_id, type, actor_id, entity_id, text, read, created_at)
likes           (id, post_id, user_id, created_at)
saved_posts     (id, post_id, user_id, saved_at)
comments        (id, post_id, user_id, text, created_at)
circles         (id, user_id, name, created_at)
circle_members  (id, circle_id, member_id, created_at)
```

All tables have Row Level Security enabled. 20 migration files in `supabase/migrations/`.

### Known architectural problems

1. **Single-file fragility** — One JS parse error crashes the entire app (happened twice in development). `const` shadowing, missing semicolons, typos — all fatal.
2. **Global state** — ~40 module-level variables (`currentUser`, `posts`, `events`, `contacts`, `groupDefs`…). No encapsulation. Race conditions possible on auth state changes.
3. **Demo/real user data interleaved** — Large arrays of hardcoded demo data (`_DEMO_POSTS`, `_DEMO_CONTACTS`, `_DEMO_EVENTS`) are guarded by `isDemoAccount` checks scattered throughout the codebase.
4. **No type safety** — All Supabase responses are untyped. Field name typos cause silent bugs.
5. **DOM as state** — `getElementById` used for reading state (e.g. `followerCount.textContent`). No single source of truth.
6. **Inline event handlers** — `onclick="..."` strings in HTML, making refactoring dangerous.
7. **Scaling limit** — At 10,800 lines, further meaningful features are increasingly risky to add.

---

## Target architecture (Next.js)

### Stack decisions

| Layer | Choice | Rationale |
|---|---|---|
| Framework | Next.js 14+ (App Router) | SSR, file-based routing, React ecosystem, first-class Vercel support |
| Language | TypeScript | Catches bugs at compile time; Supabase can generate types from schema |
| Styling | Tailwind CSS | Consistent with design tokens already established; utility-first matches the UI patterns |
| Auth | Supabase Auth (`@supabase/ssr`) | Existing auth unchanged; SSR package gives server-side session |
| Database | Supabase PostgreSQL (existing) | All migrations, RLS, RPC functions carry forward unchanged |
| Storage | Supabase Storage (existing) | `avatars` and `posts` buckets unchanged |
| Realtime | Supabase Realtime | Feed + notification subscriptions, cleaner in component model |
| Global state | Zustand | Lightweight typed store; replaces ~40 global variables |
| Images | Next.js Image | Automatic optimisation, lazy loading, responsive sizes |
| KYC | Onfido SDK | Real video verification; replaces fake timer implementation |
| Deployment | Vercel (existing) | No change; crons available on Pro plan |

### Folder structure

```
hatch-web/                          # New Next.js project (separate repo recommended)
├── app/
│   ├── (auth)/                     # No nav bar
│   │   ├── login/page.tsx
│   │   ├── register/page.tsx
│   │   └── verify/page.tsx         # KYC via Onfido
│   ├── (app)/                      # With bottom nav bar
│   │   ├── layout.tsx              # Shell: TopNav + BottomNav
│   │   ├── feed/page.tsx           # Home feed + sub-nav
│   │   ├── events/page.tsx         # Calendar + events list
│   │   ├── notifications/page.tsx  # Follow requests + notifications
│   │   ├── messages/page.tsx       # Chat (Phase 2)
│   │   └── profile/
│   │       ├── page.tsx            # Own profile
│   │       └── [id]/page.tsx       # User/outlet profile
│   ├── api/
│   │   ├── fetch-news/route.ts     # RSS ingestion (port of existing)
│   │   └── onfido/webhook/route.ts # KYC result handler
│   └── layout.tsx                  # Root layout + providers
├── components/
│   ├── feed/
│   │   ├── Feed.tsx                # Feed container + realtime sub
│   │   ├── PostCard.tsx            # Post card (photo, pulse, news)
│   │   ├── DiaryStrip.tsx          # Diary rings at top of feed
│   │   └── FeedSubNav.tsx          # Personal / Pulse / News / Explore
│   ├── post/
│   │   ├── CreatePostModal.tsx     # Photo post creation
│   │   ├── CreatePulseModal.tsx    # Pulse post creation
│   │   ├── AudiencePicker.tsx      # Everyone / Circles / Event
│   │   └── ImageUpload.tsx         # Multi-image with carousel preview
│   ├── profile/
│   │   ├── ProfileHeader.tsx       # Avatar, name, stats, buttons
│   │   ├── ProfileGrid.tsx         # Posts/Pulse/Tagged/Saved tabs
│   │   └── AvatarUpload.tsx        # Upload + crop
│   ├── events/
│   │   ├── Calendar.tsx            # Month + week views
│   │   ├── EventCard.tsx           # Event with RSVP
│   │   └── CreateEventModal.tsx
│   ├── notifications/
│   │   ├── NotificationList.tsx
│   │   └── FollowRequestCard.tsx
│   ├── circles/
│   │   ├── CircleManager.tsx       # Manage circles
│   │   └── CirclePicker.tsx        # Audience selector
│   └── ui/
│       ├── BottomNav.tsx
│       ├── TopNav.tsx
│       ├── Modal.tsx
│       ├── Toast.tsx
│       ├── Avatar.tsx
│       ├── Button.tsx
│       └── Skeleton.tsx
├── lib/
│   ├── supabase/
│   │   ├── client.ts               # Browser client (singleton)
│   │   ├── server.ts               # Server client (SSR)
│   │   └── types.ts                # Generated: `supabase gen types typescript`
│   ├── hooks/
│   │   ├── useUser.ts
│   │   ├── useFeed.ts              # Feed + realtime
│   │   ├── useFollows.ts
│   │   ├── useNotifications.ts     # Notifications + realtime
│   │   └── useCircles.ts
│   └── utils/
│       ├── upload.ts               # Storage helpers
│       ├── format.ts               # Dates, numbers
│       └── news.ts                 # RSS parsing (port of fetch-news.js)
├── store/
│   └── useAppStore.ts              # Zustand: currentUser, toasts, modal state
├── supabase/
│   └── migrations/                 # All 20 existing migrations carry forward
├── public/
├── tailwind.config.ts
├── next.config.ts
└── tsconfig.json
```

### State management

Replace the ~40 global JS variables with:

```ts
// store/useAppStore.ts (Zustand)
interface AppStore {
  currentUser: User | null
  toasts: Toast[]
  activeModal: string | null
  setUser: (user: User | null) => void
  addToast: (msg: string) => void
  openModal: (id: string) => void
  closeModal: () => void
}

// lib/hooks/useFeed.ts (Tanstack Query or SWR + Supabase Realtime)
// lib/hooks/useNotifications.ts
// lib/hooks/useFollows.ts (per-profile)
// lib/hooks/useCircles.ts
```

### Auth flow

```
middleware.ts → check Supabase session cookie
  → no session → redirect to /login
  → session exists → allow through to (app) routes

(auth) routes → no middleware check → always accessible
```

### Key migrations from prototype patterns

| Prototype pattern | Next.js equivalent |
|---|---|
| `enterApp()` / `showAuthScreen()` | Middleware + route groups |
| `document.getElementById(...)` mutations | React state + controlled components |
| `notifications.unshift(...)` + `renderNotifs()` | Zustand slice + React re-render |
| `supabaseClient.from('posts').select(...)` everywhere | `useFeed()` hook, data fetched once |
| `isDemoAccount` guards | Remove entirely — demo mode not needed in production |
| `currentUser.*` global variables | `useAppStore().currentUser` |
| `showToast('...')` | `useAppStore().addToast(...)` |
| `openModal('...')` | `useAppStore().openModal(...)` |

---

## Supabase changes needed for Next.js migration

Minimal — the schema is largely sound. Key additions:

| Addition | Reason |
|---|---|
| `profiles.handle` column (HAT-XXXXXX) | Unique user handle for profile URLs |
| `get_circle_owners_for_member` RPC | Already exists (migration 018) |
| Onfido webhook handler | New API route to set `profiles.verified = true` |
| Row-level cron job (pg_cron) | 24-hour diary expiry on Supabase |

Do **not** change: existing tables, RLS policies, storage buckets, outlet account UUIDs.
