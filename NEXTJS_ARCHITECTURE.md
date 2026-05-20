# Hatch — Next.js Migration Architecture Proposal

This document is a starting point for the conversation with Jack about migrating from the single HTML prototype to a proper Next.js + Supabase architecture. It is not prescriptive — Jack should own the final decisions. The goal is to arrive at that conversation with a clear picture of what we have, what we need, and one well-reasoned proposal to react to.

---

## Why migrate now

The single HTML file has served its purpose. At ~10,000 lines it is approaching the limit of what can be safely maintained:

- Every change risks breaking unrelated features due to shared global state
- Claude Code has to grep and sed its way around the file rather than working on isolated components
- KYC video capture, real-time feed updates, and Trusted Circles filtering are all significantly harder to implement cleanly in a single file
- Any future engineer joining the team would struggle to orient themselves
- A mobile app (Phase 2) is much easier to build alongside a proper component architecture

The Supabase project stays exactly as-is. The database, auth, storage and all migrations are unaffected by this migration. Only the frontend changes.

---

## Proposed stack

| Layer | Choice | Rationale |
|---|---|---|
| Framework | Next.js 14 (App Router) | Industry standard, excellent Supabase integration, SSR for SEO, easy Vercel deployment |
| Language | TypeScript | Catches bugs at build time, much safer for a growing codebase, Jack will expect it |
| Styling | Tailwind CSS | Utility-first, fast to build with, consistent with the existing design tokens |
| Auth | Supabase Auth (existing) | No change — SSR helpers available via `@supabase/ssr` |
| Database | Supabase (existing) | No change — same tables, same RLS policies |
| Storage | Supabase Storage (existing) | No change — same buckets |
| Real-time | Supabase Realtime | Feed subscriptions, notifications — much cleaner in a component model |
| KYC verification | Onfido | Third-party KYC provider — document + liveness check, GDPR compliant, used by Monzo and Revolut |
| State | Zustand | Lightweight global state for current user, feed, notifications — replaces the current global JS variables |
| Image handling | Next.js Image component | Automatic optimisation, lazy loading |
| Deployment | Vercel (existing) | No change |

---

## Folder structure

```
hatch/
├── app/                          # Next.js App Router
│   ├── (auth)/                   # Auth group — no nav bar
│   │   ├── login/
│   │   │   └── page.tsx
│   │   ├── register/
│   │   │   └── page.tsx
│   │   └── verify/               # KYC video verification
│   │       └── page.tsx
│   ├── (app)/                    # Main app group — with nav bar
│   │   ├── layout.tsx            # Shell with bottom nav bar
│   │   ├── feed/
│   │   │   └── page.tsx          # Home feed
│   │   ├── events/
│   │   │   └── page.tsx          # Events + calendar
│   │   ├── create/
│   │   │   └── page.tsx          # Post / event creation
│   │   ├── messages/
│   │   │   └── page.tsx          # Messages
│   │   ├── notifications/
│   │   │   └── page.tsx          # Notifications + follow requests
│   │   └── profile/
│   │       ├── page.tsx          # Own profile
│   │       └── [id]/
│   │           └── page.tsx      # Friend profile
│   └── layout.tsx                # Root layout
├── components/
│   ├── feed/
│   │   ├── FeedPost.tsx          # Individual post card
│   │   ├── FeedList.tsx          # Feed scroll container
│   │   └── AlgorithmDial.tsx     # Chrono ↔ suggested slider
│   ├── profile/
│   │   ├── ProfileHeader.tsx     # Avatar, name, stats, buttons
│   │   ├── ProfileGrid.tsx       # Posts grid
│   │   └── ProfileSubNav.tsx     # Posts / Pulse / Tagged tabs
│   ├── post/
│   │   ├── CreatePostModal.tsx   # Post creation
│   │   ├── AudiencePicker.tsx    # Everyone / Circles / Event
│   │   └── ImageUpload.tsx       # Multi-image carousel upload
│   ├── circles/
│   │   ├── CircleManager.tsx     # Create / edit circles
│   │   └── CirclePicker.tsx      # Per-post audience selector
│   ├── kyc/
│   │   └── OnfidoVerification.tsx # Onfido SDK wrapper + webhook handling
│   ├── notifications/
│   │   ├── NotificationList.tsx
│   │   └── FollowRequestCard.tsx # Approve / decline UI
│   ├── collections/
│   │   ├── CollectionStrip.tsx   # Profile collections row
│   │   └── CollectionModal.tsx   # Create / edit collection
│   └── ui/                       # Shared primitives
│       ├── Button.tsx
│       ├── Avatar.tsx
│       ├── Toast.tsx
│       ├── Modal.tsx
│       └── BottomNav.tsx
├── lib/
│   ├── supabase/
│   │   ├── client.ts             # Browser Supabase client
│   │   ├── server.ts             # Server Supabase client (SSR)
│   │   └── types.ts              # Generated DB types (supabase gen types)
│   ├── hooks/
│   │   ├── useUser.ts            # Current user state
│   │   ├── useFeed.ts            # Feed with realtime subscription
│   │   ├── useFollows.ts         # Follow state + counts
│   │   ├── useNotifications.ts   # Notifications with realtime
│   │   └── useCircles.ts         # Circles for current user
│   └── utils/
│       ├── upload.ts             # Supabase Storage helpers
│       ├── format.ts             # Date, number formatting
│       └── generateId.ts         # HAT-XXXXXX user ID generation
├── store/
│   └── useAppStore.ts            # Zustand global store
├── supabase/
│   └── migrations/               # Existing migrations stay here
├── public/
├── CLAUDE.md
├── TASKS.md
└── NEXTJS_ARCHITECTURE.md
```

---

## Key architectural decisions

### 1. App Router over Pages Router
Next.js 14 App Router is the current standard. It enables React Server Components which means profile pages, post grids and public content can be server-rendered — faster initial load and better SEO. Auth-protected routes use middleware.

### 2. Route groups for auth vs app shell
Two route groups: `(auth)` for login/register/verify (no nav bar), and `(app)` for everything inside the app (shared layout with bottom nav bar). This replaces the current `showAuthScreen()` / `enterApp()` toggle.

### 3. Supabase SSR helpers
The `@supabase/ssr` package provides server-side session handling. This replaces the current `onAuthStateChange` listener and means the session is available on first render rather than after a client-side check.

### 4. Zustand for global state
Currently the app uses a large number of global JS variables (`currentUser`, `posts`, `events`, `notifications` etc.). Zustand provides a lightweight, typed equivalent that works cleanly with React components. One store, clearly structured.

### 5. Supabase Realtime for feed + notifications
The current feed requires a page refresh for new posts. With Supabase Realtime, a subscription on the `posts` table (filtered to followed users) pushes new posts to the feed in real time. Same approach for notifications. This is the feature users will notice most.

### 6. TypeScript throughout
The current codebase has no types. Supabase can auto-generate TypeScript types from the database schema using `supabase gen types typescript`. This means every query is typed, every component knows exactly what data it receives, and bugs are caught at build time rather than runtime.

### 7. Onfido for KYC verification
The current HTML prototype has a fake KYC implementation — no real camera capture, no video upload. Rather than building this from scratch, Hatch should use **Onfido**, the same KYC provider used by Monzo, Revolut and Starling.

**Why Onfido:**
- Covers document verification + liveness check (the selfie/video step) in one flow
- JavaScript SDK integrates directly into the Next.js app — no redirect to a third-party URL
- GDPR compliant and UK-regulated — important for investor credibility
- Hatch never handles raw video or document data — Onfido holds it, which is better for privacy
- Sandbox/test mode available for development — no cost per check during testing
- Pricing approximately £1–3 per verification at low volumes

**How it works in practice:**
1. User completes registration
2. Hatch backend calls Onfido API to create an applicant and returns an SDK token
3. Onfido SDK launches in the browser — handles camera access, liveness check, document scan
4. Onfido sends a webhook to a Hatch API route with the verification result
5. Hatch API route updates `profiles.verified = true` on approval

This approach means the `kyc-videos` Supabase Storage bucket is no longer needed — Onfido manages all verification media. The only Supabase change needed is the `profiles.verified` column.

**Alternatives considered:**
- **Sumsub** — strong alternative, competitive pricing, good developer experience
- **Jumio** — enterprise tier, longer sales process, likely overkill at this stage
- **Build in-house** — not recommended; compliance risk, significant engineering effort, no credibility with investors

---

## Migration approach

The recommended approach is a clean rebuild, not a port. The HTML file becomes a reference document — copy the logic, not the code.

**Sequence:**
1. Jack sets up the Next.js project with the folder structure above
2. Auth flows first (login, register, KYC) — these are the entry point for everything else
3. Feed next — this is the core of the product and where Realtime adds the most value
4. Profile (own + friend) — reuse `ProfileHeader` and `ProfileGrid` components
5. Post creation — `CreatePostModal`, `AudiencePicker`, `ImageUpload`
6. Circles, Collections, Events — in parallel once core is stable
7. Notifications — follow requests, event invites

**What not to do:**
- Do not copy-paste JS from the HTML file. Rewrite each function as a typed hook or utility.
- Do not skip TypeScript. The short-term cost is worth the long-term benefit.
- Do not build Phase 2 features during migration. Scope is exactly what exists today, rebuilt cleanly.

---

## Supabase changes needed at migration

The existing schema is largely sound. A few additions will be needed that are already in the TASKS.md backlog:

| Addition | Why |
|---|---|
| `follow_requests` table | Follow request flow |
| `collections` + `collection_items` tables | Collections persistence |
| `invite_codes` table | Invite gate at signup |
| `circles` + `circle_members` tables | Trusted Circles persistence |
| `notifications` table | Persistent notifications |
| `profiles.verified` column | KYC status — set to true by Onfido webhook |
| `profiles.handle` column | Unique HAT-XXXXXX ID |

Note: the `kyc-videos` Storage bucket is no longer needed — Onfido manages all verification media.

---

## What this unlocks for Phase 2

Building on Next.js + Supabase makes the following Phase 2 features significantly easier:

- **React Native mobile app** — shared hooks and Supabase client between web and mobile
- **Diary (ephemeral posts)** — Supabase Realtime + scheduled functions for 24-hour expiry
- **DMs** — Supabase Realtime channels
- **Feed Switch** (Instagram import) — can be a separate Next.js app sharing the same Supabase project
- **Feed+ subscriptions** — Stripe integration is well-documented for Next.js
- **QR ID card** — server-rendered page with dynamic OG image

---

## Open questions for Jack

These are the decisions that should be Jack's:

1. **App Router vs Pages Router** — proposal above uses App Router; Jack may prefer Pages Router for familiarity
2. **Tailwind vs CSS Modules** — Tailwind is proposed; Jack may prefer CSS Modules or styled-components
3. **Zustand vs React Context** — Zustand is proposed for simplicity; Jack may have a preference
4. **Mobile-first or web-first** — proposal assumes web-first with mobile app to follow; if Jack wants to go React Native from day one, the architecture shifts
5. **Monorepo** — if mobile app is planned soon, a Turborepo monorepo (`apps/web`, `apps/mobile`, `packages/shared`) makes sense from the start
6. **Testing** — no testing framework is specified above; Jack should decide on Vitest + React Testing Library or equivalent
7. **Onfido vs Sumsub** — Onfido is proposed as the KYC provider; Sumsub is a credible alternative worth comparing on pricing and developer experience before committing
8. **Onfido webhook handling** — the verification result arrives via webhook to a Hatch API route; Jack needs to decide whether this lives in Next.js API routes or a separate Supabase Edge Function

---

*Last updated: May 2026. This document should be reviewed with Jack before any migration work begins.*
