# Hatch — Product Document

## Vision

Hatch is a privacy-first social platform for people who want to share with people they actually know, without algorithmic manipulation, data selling, or behavioural advertising.

**Tagline:** *Your content. Your rules.*

**Core proposition:** Verified-identity, chronological, algorithm-free social networking with user-controlled audiences.

**Target demographic:** 25–40, UK-first, privacy-forward professionals.

---

## What makes Hatch different

| Principle | How it manifests |
|---|---|
| No algorithmic feed | Chronological by default; optional Explore blend is user-controlled |
| No data selling | Business model is subscriptions, not advertising |
| Verified identity | KYC at signup — one real person per account |
| User-controlled audiences | Every post targets: Everyone / Trusted Circles / Event attendees |
| Invite-only growth | Invite codes gate signup — controlled, high-trust community |

---

## Product areas

### 1. Authentication
- Invite-code gated signup
- 3-step flow: account creation → email OTP → video identity verification (KYC)
- Login, logout, password reset
- "Continue as" quick login for returning users

### 2. Home Feed
Four sub-modes the user switches between:
- **Personal** — posts from followed users only, chronological
- **Pulse** — short text posts (≤150 chars) from followed users
- **News** — articles from followed outlet accounts (BBC News, The Guardian)
- **Explore** — algorithm-blended mix (personal + pulse + news, user-controlled ratio)

Feed features: like, comment, save, share; realtime new-post injection; multi-image carousel posts

### 3. Diary
- Ephemeral 24-hour photo/caption posts
- Visible as ring avatars in the diary strip above the feed
- Only visible to the owner and optionally to followers
- Private by design — stored with `visibility: 'private'`

### 4. Post Creation
- Speed dial: Diary / Photo post / Event / Pulse post
- Photo posts: single or multi-image carousel, caption, audience picker
- Pulse posts: text-only ≤150 chars, audience picker
- Audience picker: Everyone (public) / Circles (friends-only) / Event attendees

### 5. Trusted Circles
- User-defined named groups (e.g. "Family", "Close Friends", custom)
- Seeded at registration with "Family" and "Close Friends"
- Posts with audience = Circles are only shown to users in the poster's circles
- Circle management: create, rename, delete, add/remove members

### 6. Events
- Create events: title, description, location, start/end time, visibility (public/followers/invite-only)
- Calendar view (month + week views) with event dots and RSVP status colours
- Event cards with RSVP (Going / Maybe / Declined)
- Invite search: find followed users to invite
- Availability polling: ask friends when they're free before finalising a date

### 7. News Feed
- BBC News and The Guardian modelled as outlet accounts in Supabase
- Users follow outlets to see their articles in the News tab
- Articles ingested hourly via `api/fetch-news.js` (Vercel serverless, 5 RSS feeds)
- Articles display: headline, snippet, thumbnail, "Read full article →" link
- No full article text stored — snippet/description only

### 8. Profile
- Own profile: avatar, name, bio, followers/following/post counts
- Post grid (Photos / Pulse / Tagged / Saved tabs)
- Diary strip on profile
- Collections strip (grouped saved posts)
- Privacy setting: public / private
- Verified badge (KYC)

### 9. Follow Graph
- Follow public accounts instantly
- Follow private accounts via request → approve/decline flow
- Followers/following modals with tappable user rows
- Unfollow, withdraw request

### 10. Notifications
- Follow request received / approved
- Event invites
- Persistent to Supabase; marked read on tab open
- Bell badge in top nav

### 11. Messages
- Chat UI exists in prototype (demo data only)
- Not wired to Supabase — deferred to Phase 2

### 12. Search
- User search by name (Supabase `ilike`)
- Post and event search (local/demo for now)
- Live search results overlay

### 13. Collections
- Save posts into named collections
- Collections strip on profile page
- Persisted to Supabase `collections` + `collection_items` tables

### 14. KYC Video Verification
- UI exists (3-step auth card with video recording step)
- Current implementation is fake (no real camera capture)
- P3 item: replace with Onfido SDK

### 15. Explore / Algorithm Dial
- Tab strip currently (Personal / Pulse / News / Explore)
- Explore blends post types by user-controlled ratio
- Topics modal lets users tune the blend
- Roadmap: replace with chronological ↔ suggested slider

### 16. AI Assistant
- Text input UI at bottom of screen
- Handles natural language navigation ("go to events", "show my profile")
- Limited — navigational only, no real AI backend

---

## Phase 1 MVP status (as of Sep 2026)

All Phase 1 items are implemented in the prototype:

| Feature | Status |
|---|---|
| Profile + posting | ✅ Live |
| Follow graph + follow requests | ✅ Live |
| Trusted Circles | ✅ Live |
| Collections | ✅ Live |
| Invite code system | ✅ Live |
| Home feed (Supabase) | ✅ Live |
| Auth (signup/login/reset) | ✅ Live |
| Avatar upload prompt post signup | ✅ Live |
| News feed (outlets + RSS) | ✅ Live |
| KYC video verification | ⚠️ Fake UI (P3) |
| Algorithm dial (real slider) | ⚠️ Tab strip only (P3) |

## Phase 2 (deferred)

- Diary expiry (24-hour deletion)
- DMs (Messages tab, currently demo-only)
- Memories archive
- QR ID card
- Feed Switch (Instagram import)
- Feed+ subscriptions
- React Native mobile app

---

## Infrastructure

| Component | Detail |
|---|---|
| Frontend | Single `index.html` — vanilla JS + inline CSS, ~10,800 lines |
| Backend | Supabase (auth, PostgreSQL, storage, realtime) |
| Hosting | Vercel — https://totem-frontend-five.vercel.app/ |
| News ingestion | `api/fetch-news.js` serverless function, triggered manually or via cron |
| Events pipeline | `events_pipeline/` — venue scraper (separate, not deployed) |
| Database | 20 applied migrations in `supabase/migrations/` |
| Tests | `tests/supabase_test_suite.js` — 39 tests, 36 pass |

---

## Supabase project

- URL: `https://ocztxpmmbopcbtshetts.supabase.co`
- Outlet account UUIDs:
  - BBC News: `a0000000-0000-0000-0000-000000000001`
  - The Guardian: `a0000000-0000-0000-0000-000000000002`
