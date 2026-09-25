# Hatch — Feature Inventory

Status key:
- ✅ **Working** — implemented and functional in production
- ⚠️ **Partial** — implemented but incomplete or buggy
- 🔲 **Stub** — UI exists, no real backend connection
- ❌ **Missing** — in roadmap, not yet built

---

## Authentication

| Feature | Status | Notes |
|---|---|---|
| Login with email + password | ✅ | `doLogin()`, Supabase auth |
| Signup with invite code | ✅ | `startRegistration()` validates against `invite_codes` table |
| Email OTP verification | ✅ | `verifyOtp()` — Supabase sends email OTP |
| Password reset | ✅ | PKCE flow, `submitNewPassword()` |
| "Continue as" quick login | ✅ | Shows returning user row on auth screen |
| KYC video verification | 🔲 | Fake timer + flag — no real camera/upload. P3 item. |
| Logout | ✅ | `supabase.auth.signOut()` |
| Session persistence | ✅ | `onAuthStateChange` listener |

---

## Feed

| Feature | Status | Notes |
|---|---|---|
| Personal feed (followed users) | ✅ | `loadFeedFromSupabase()` |
| Feed ordered chronologically | ✅ | `created_at DESC` |
| Feed limited to followed users | ✅ | `.in('user_id', followedIds)` |
| Realtime new post injection | ✅ | `subscribeFeedRealtime()` Supabase channel |
| Audience filtering (friends-only posts) | ✅ | P2-6: `_feedInCircleOf` set, RPC lookup |
| Pulse sub-feed | ✅ | `feed_type = 'pulse'` filter |
| News sub-feed | ✅ | Outlet accounts, `feed_type = 'news'` |
| Explore feed (blended) | ✅ | `buildExploreQueue()` — weighted interleaving |
| Feed skeleton loading | ✅ | Shimmer cards while fetching |
| Empty state | ✅ | "Follow people to see their posts here" |
| Demo mode (hardcoded posts) | ✅ | `isDemoAccount` guard, `_DEMO_POSTS` array |

---

## Posts

| Feature | Status | Notes |
|---|---|---|
| Create photo post | ✅ | Single or multi-image |
| Create text-only post | ✅ | `image_url: null` |
| Create pulse post | ✅ | `#pulsePostModal`, `feed_type: 'pulse'` |
| Audience picker (Everyone) | ✅ | `visibility: 'public'` |
| Audience picker (Circles) | ✅ | `visibility: 'friends'` |
| Audience picker (Event attendees) | ⚠️ | UI exists, maps to `'friends'` — event-specific RLS not implemented |
| Multi-image carousel | ✅ | `JSON.stringify(urls)` in `image_url`, `parseImageUrls()` |
| EXIF data display | ✅ | `exifr` library, details popover |
| AI content declaration | ✅ | Toggle on post modal |
| Tag people in posts | ⚠️ | UI exists, demo only — not stored/queried from Supabase |
| Like a post | ✅ | Optimistic + Supabase `likes` table |
| Comment on post | ✅ | `comments` table, `loadComments()` |
| Save a post | ✅ | `saved_posts` table, optimistic |
| Share a post | ⚠️ | `openSendPost()` — UI only, no real send |
| Delete a post | ❌ | Not implemented |
| Edit a post | ❌ | Not implemented |
| News post "Read full article" link | ✅ | `external_url` column, opens new tab |

---

## Diary

| Feature | Status | Notes |
|---|---|---|
| Create diary entry (photo + caption) | ✅ | Upload to Storage, `feed_type: 'diary'` |
| Diary strip in feed | ✅ | Own ring + followed users' rings |
| 24-hour expiry | 🔲 | Stored as regular posts — no deletion job runs |
| Diary viewer (fullscreen) | ✅ | `openDiaryViewer()` |
| Privacy (owner-only) | ✅ | `visibility: 'private'`, RLS policy 007 |
| Profile diary strip | ✅ | `loadProfileDiaries()` |

---

## Events

| Feature | Status | Notes |
|---|---|---|
| Create event | ✅ | Title, description, location, date/time, visibility |
| Calendar month view | ✅ | `renderCalendar()`, opens on current month |
| Calendar week view | ✅ | `renderWeekView()` |
| Event cards + RSVP | ✅ | Going / Maybe / Declined |
| Invite-only events | ⚠️ | `event_invites` table write works; read RLS restricts invitee visibility |
| Invite search (followed users) | ✅ | `loadFollowersForPicker()`, live name filter |
| Availability polling | ⚠️ | UI exists (`openAvailabilityModal()`), not connected to Supabase |
| Event notifications to invitees | ✅ | `notifications` insert on event create |
| Events from Supabase | ✅ | `loadEventsFromSupabase()` |
| Explore events (venue discovery) | 🔲 | `events_pipeline/` scraper exists but not deployed/integrated |
| Time picker 5-min snap | ✅ | `step="300"`, `snapMin()` helper |

---

## Follow graph

| Feature | Status | Notes |
|---|---|---|
| Follow public account | ✅ | Instant, `follows` table |
| Follow private account (request flow) | ✅ | `follow_requests` → approve/decline |
| Unfollow | ✅ | Delete from `follows` |
| Withdraw follow request | ✅ | Delete from `follow_requests` |
| Approve/decline follow request | ✅ | Updates `follow_requests`, inserts into `follows` |
| Follow request notification | ✅ | Writes to `notifications` table |
| Follow approved notification | ✅ | Writes to `notifications` table |
| Follower/following counts | ✅ | Live from Supabase on profile open |
| Followers/following modals | ✅ | Tappable user rows, real users load from Supabase |
| Outlet accounts auto-accept | ✅ | `privacy: 'public'` means instant follow |

---

## Trusted Circles

| Feature | Status | Notes |
|---|---|---|
| Circles persisted to Supabase | ✅ | `circles` + `circle_members` tables |
| Default circles at registration | ✅ | "Family" + "Close Friends" seeded in `finishRegistration()` |
| Create circle | ✅ | `addNewGroup()` |
| Rename circle | ✅ | `saveCurrentGroup()` |
| Delete circle | ✅ | `deleteCurrentGroup()` |
| Add members to circle | ⚠️ | `circle_members` table writes exist; UI for adding members from followed list is incomplete |
| Audience filter in feed | ✅ | P2-6 with SECURITY DEFINER RPC |

---

## Profile

| Feature | Status | Notes |
|---|---|---|
| Own profile header | ✅ | Avatar, name, bio, stats |
| Avatar upload | ✅ | Supabase Storage `avatars` bucket |
| Name/bio edit | ✅ | Supabase `profiles` update |
| Privacy setting (public/private) | ✅ | Persisted to `profiles.privacy` |
| Profile posts grid | ✅ | Real posts from Supabase |
| Profile Pulse tab | ✅ | Filters from in-memory `posts` array |
| Profile Saved tab | ✅ | `loadSavedPostsForProfile()` |
| Profile Tagged tab | ⚠️ | Demo only — not queried from Supabase |
| Verified badge | 🔲 | Hardcoded to demo profile |
| Collections strip | ✅ | `loadCollectionsFromSupabase()` |
| Follower/post counts | ✅ | Supabase `count` queries on login |
| Friend profile (any user) | ✅ | `openFriendProfile()`, `loadFriendPostsFromSupabase()` |
| Friend profile news list view | ✅ | Outlet posts render as article list |

---

## Notifications

| Feature | Status | Notes |
|---|---|---|
| Follow request notification | ✅ | Shown in Follow Requests card |
| Follow approved notification | ✅ | `notifications` table |
| Event invite notification | ✅ | Writes to invitee's `notifications` |
| Mark as read on open | ✅ | Supabase UPDATE on tab open |
| Reload on tab open | ✅ | `loadNotificationsFromSupabase()` called on open |
| Badge count in top nav | ✅ | `updateNotifBadge()` |

---

## Search

| Feature | Status | Notes |
|---|---|---|
| User search (Supabase) | ✅ | `ilike('name', ...)` with 8s timeout |
| User search (local contacts) | ✅ | Demo contacts fallback |
| Post search | ⚠️ | Local/demo only |
| Event search | ⚠️ | Local/demo only |
| Open searched user profile | ✅ | `openSearchedProfile()` → `openFriendProfile()` |

---

## Collections

| Feature | Status | Notes |
|---|---|---|
| Create collection | ✅ | `addCollection()`, Supabase insert |
| Load collections | ✅ | `loadCollectionsFromSupabase()` |
| Collections strip on profile | ✅ | Horizontal scroll |
| Add posts to collection | ⚠️ | `collection_items` table exists; UI for adding posts not built |

---

## News

| Feature | Status | Notes |
|---|---|---|
| Outlet profiles (BBC, Guardian) | ✅ | Migration 019, fixed UUIDs |
| RSS ingestion serverless function | ✅ | `api/fetch-news.js`, 5 feeds |
| Hourly cron schedule | ❌ | Requires Vercel Pro — triggered manually for now |
| News gated by follow status | ✅ | `_followedIds` intersection |
| "Read full article" link | ✅ | `external_url` column |
| Deduplication | ✅ | `external_url` check before insert |
| Outlet profile page (article list) | ✅ | `loadFriendPostsFromSupabase()` news layout |

---

## Messages

| Feature | Status | Notes |
|---|---|---|
| Chat UI | 🔲 | Exists with demo data, not Supabase-connected |
| Send message | ❌ | Not implemented |
| Real-time messaging | ❌ | Phase 2 |

---

## AI Assistant

| Feature | Status | Notes |
|---|---|---|
| Natural language navigation | ✅ | Handles tab switching, profile opening |
| Real AI responses | 🔲 | Pattern-matched only, no LLM backend |

---

## Infrastructure / Developer

| Feature | Status | Notes |
|---|---|---|
| Supabase test suite | ✅ | 39 tests, 36 pass (3 skipped — need TEST_USER_2_ID) |
| Backup protocol | ✅ | Timestamped backups in `backups/` |
| Vercel auto-deploy from GitHub | ✅ | Connected to `main` branch |
| Environment variables (Vercel) | ✅ | `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, `CRON_SECRET` |
