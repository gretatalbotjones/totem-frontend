# Feature Inventory

Status definitions:
- **working** — implemented and functional in production with real Supabase data
- **partial** — implemented but incomplete (missing edge cases, some paths broken)
- **buggy** — implemented but has known defects affecting real users
- **broken** — exists in UI but does not function
- **stub** — UI exists, no backend connection at all

Priority: **P0** = blocks real users / **P1** = important for MVP / **P2** = enhancement / **P3** = post-MVP

---

## Authentication

| Feature | Status | Priority | Notes |
|---|---|---|---|
| Email + password login | working | P0 | `doLogin()`, Supabase auth |
| Signup with invite code | working | P0 | Validates against `invite_codes` table |
| Email OTP verification | working | P0 | Supabase sends OTP, `verifyOtp()` |
| Password reset | working | P0 | PKCE flow, URL-based |
| "Continue as" returning user | working | P1 | Shows known account row on auth screen |
| KYC video verification | broken | P1 | Fake timer, no real camera, no upload — P3 item |
| Logout | working | P0 | `supabase.auth.signOut()` |

---

## Feed

| Feature | Status | Priority | Notes |
|---|---|---|---|
| Personal feed (followed users) | working | P0 | Loads from Supabase, chronological |
| Realtime new post injection | working | P1 | Supabase Realtime channel |
| Friends-only post filtering | working | P1 | P2-6: SECURITY DEFINER RPC + client-side filter |
| Skeleton loading | working | P1 | Fixed — emptyMsg preservation bug was patched |
| Pulse sub-feed | working | P1 | `feed_type = 'pulse'` filter |
| News sub-feed (BBC + Guardian) | working | P1 | Outlet accounts, RSS-ingested, follow-gated |
| Explore feed (blended) | working | P2 | Weighted interleaving of post types |
| Demo mode (hardcoded posts) | working | — | Demo account only, gated by `isDemoAccount` |

---

## Posts

| Feature | Status | Priority | Notes |
|---|---|---|---|
| Create photo post (single) | working | P0 | Uploads to Supabase Storage |
| Create photo post (multi-image carousel) | working | P1 | `JSON.stringify(urls)` in `image_url` |
| Create text-only post | working | P0 | `image_url: null` |
| Create pulse post (≤150 chars) | working | P1 | `#pulsePostModal`, `feed_type: 'pulse'` |
| Audience picker — Everyone | working | P0 | `visibility: 'public'` |
| Audience picker — Circles | working | P1 | `visibility: 'friends'`, RLS-filtered in feed |
| Audience picker — Event attendees | partial | P2 | Maps to `'friends'` — no event-specific filtering |
| Like a post | working | P1 | Optimistic + rollback, `likes` table |
| Comment on a post | working | P1 | `comments` table, loads real avatars/names |
| Save a post | working | P1 | `saved_posts` table, optimistic |
| Share a post | broken | P2 | UI exists, no real send mechanism |
| Delete a post | broken | P2 | Not implemented |
| Edit a post | broken | P2 | Not implemented |
| Tag people in posts | partial | P2 | UI exists, not stored to Supabase |
| "Read full article" link (news) | working | P1 | `external_url` column, opens new tab |

---

## Diary

| Feature | Status | Priority | Notes |
|---|---|---|---|
| Create diary entry (photo + caption) | working | P1 | Uploads to Storage, `visibility: 'private'` |
| Diary strip in feed | working | P1 | Own ring + followed users |
| Diary viewer (fullscreen) | working | P1 | `openDiaryViewer()` |
| 24-hour auto-expiry | broken | P2 | Stored indefinitely — no deletion job |
| Profile diary strip | working | P2 | `loadProfileDiaries()` |

---

## Events

| Feature | Status | Priority | Notes |
|---|---|---|---|
| Create event | working | P1 | Title, location, date/time, visibility |
| Calendar (month view) | working | P1 | Opens on current month (fixed) |
| Calendar (week view) | working | P1 | `renderWeekView()` |
| Event RSVP (Going/Maybe/Declined) | working | P1 | Updates `event_invites.rsvp` |
| Invite-only event — host creates | working | P1 | `event_invites` insert works |
| Invite-only event — invitee sees it | buggy | P1 | RLS policy only allows owner to read invite events — invitees blocked |
| Invite search (live name filter) | working | P1 | `loadFollowersForPicker()` + `filterInviteList()` |
| Event invite notification to invitee | working | P1 | Writes to `notifications` table |
| Time picker 5-min snap | working | P2 | `step="300"` + `snapMin()` helper |
| Availability polling | stub | P2 | UI exists, not connected to Supabase |
| Venue explore (discovery) | stub | P3 | `events_pipeline/` scraper exists, not deployed |

---

## Follow graph

| Feature | Status | Priority | Notes |
|---|---|---|---|
| Follow public account | working | P0 | Instant, `follows` table |
| Follow private account (request flow) | working | P0 | Request → approve/decline |
| Unfollow | working | P0 | Delete from `follows` |
| Withdraw pending request | working | P1 | Delete from `follow_requests` |
| Follow request notification | working | P1 | Writes to `notifications` |
| Follow approved notification | working | P1 | Writes to `notifications` |
| Follower/following counts | working | P1 | Live Supabase count queries |
| Followers/following modal | working | P1 | Tappable rows, loads from Supabase |

---

## Trusted Circles

| Feature | Status | Priority | Notes |
|---|---|---|---|
| Circles persisted to Supabase | working | P1 | `circles` + `circle_members` tables |
| Default circles at registration | working | P1 | "Family" + "Close Friends" seeded |
| Create / rename / delete circle | working | P1 | All persist to Supabase |
| Add members to circle | partial | P1 | Table exists, picker UI does not load followed users |
| Audience filtering in feed | working | P1 | SECURITY DEFINER RPC (migration 018) |

---

## Profile

| Feature | Status | Priority | Notes |
|---|---|---|---|
| Own profile header (avatar, name, bio, stats) | working | P0 | |
| Avatar upload | working | P0 | Supabase Storage `avatars` bucket |
| Avatar sync across app on upload | working | P1 | Updates diary circle + feed cards |
| Name/bio edit | working | P0 | Persists to `profiles` |
| Privacy setting (public/private) | working | P1 | Persists to `profiles.privacy` |
| Profile posts grid | working | P1 | Loads from Supabase |
| Profile Pulse tab | working | P1 | Filters in-memory posts |
| Profile Saved tab | working | P1 | `loadSavedPostsForProfile()` |
| Profile Tagged tab | broken | P2 | Shows demo data only |
| Verified badge | broken | P2 | Hardcoded to demo profile |
| Collections strip | working | P2 | `loadCollectionsFromSupabase()` |
| Friend profile page | working | P0 | Loads posts from Supabase via `loadFriendPostsFromSupabase()` |
| Outlet profile (article list view) | working | P1 | News posts render as article list, tap opens URL |

---

## Notifications

| Feature | Status | Priority | Notes |
|---|---|---|---|
| Follow request shown | working | P0 | Card in notifications tab |
| Follow approved shown | working | P0 | `notifications` table |
| Event invite shown | working | P1 | Writes to invitee's notifications |
| Mark all read on tab open | working | P1 | Supabase UPDATE + reload |
| Notification badge in nav | working | P1 | `updateNotifBadge()` |

---

## Search

| Feature | Status | Priority | Notes |
|---|---|---|---|
| User search (Supabase) | working | P0 | `ilike('name', ...)`, 8s timeout |
| Open searched profile | working | P0 | `openSearchedProfile()` → `openFriendProfile()` |
| Post search | partial | P2 | Local/demo data only |
| Event search | partial | P2 | Local/demo data only |

---

## News

| Feature | Status | Priority | Notes |
|---|---|---|---|
| Outlet profiles (BBC, Guardian) | working | P1 | Migration 019, fixed UUIDs |
| RSS ingestion function | working | P1 | `api/fetch-news.js`, 5 feeds |
| News gated by follow status | working | P1 | `_followedIds` intersection |
| Hourly auto-cron | broken | P2 | Requires Vercel Pro — manual trigger only |
| Deduplication | working | P1 | `external_url` check before insert |

---

## Messages

| Feature | Status | Priority | Notes |
|---|---|---|---|
| Chat UI | stub | P3 | Demo data only, no Supabase connection |
| Send/receive messages | broken | P3 | Phase 2 — not built |

---

## Collections

| Feature | Status | Priority | Notes |
|---|---|---|---|
| Create collection | working | P2 | Inserts to Supabase |
| Load collections on profile | working | P2 | `loadCollectionsFromSupabase()` |
| Add posts to collection | partial | P2 | Table exists, UI to add posts not built |
