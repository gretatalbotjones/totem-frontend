# TASKS.md — Hatch Phase 1 Backlog

Work through this list top to bottom. Complete P1 tasks before moving to P2.
Mark tasks as done by changing `[ ]` to `[x]`.
After completing each task, run a backup (see CLAUDE.md backup protocol).

---

## Backup Schedule

- [x] **BACKUP-01** — Create `backups/` folder and add to `.gitignore`
- [x] **BACKUP-02** — Take a timestamped backup before starting each task session
- [x] **BACKUP-03** — Take a timestamped backup after each completed working feature

> Backup command: `cp index.html backups/index_backup_$(date +%Y%m%d_%H%M).html`

---

## P1 — Blocking (must fix before real user testing)

### ~~P1-1~~ — Post insert discards audience selection ✅
**Fixed:** Added `visibility` to the `posts.insert` payload in `submitPost()`. Maps UI values ('everyone' → 'public', 'groups'/'event' → 'friends') to DB-valid values. Captured before the async IIFE to avoid the synchronous reset of `selectedAudience` on line 5249.

---

### ~~P1-2~~ — Privacy column missing from profiles migration ✅
**Fixed:** Created `supabase/migrations/004_add_privacy_column.sql` (ALTER TABLE ADD COLUMN IF NOT EXISTS privacy TEXT NOT NULL DEFAULT 'public' CHECK IN ('public','private')). Fixed `setPrivacy()` to guard against demo account and null supabaseClient, added error logging, and added `persist` param to avoid redundant writes on load. Added `loadProfileSettings()` to fetch name/bio/privacy/avatar_url on login and call `setPrivacy(mode, false)` to restore the saved preference without re-writing it.

---

### ~~P1-3~~ — Diary images stored as base64 in DB column ✅
**Fixed:** Added `diaryFile` module-level variable. `handleDiaryPhoto()` stores the File object before FileReader runs. `openDiaryModal()` clears it on open. `submitDiaryEntry()` now uploads the file to Supabase Storage (`posts` bucket, path `{userId}/diary_{ts}.{ext}`), uses the Storage public URL for `image_url` in the DB insert, and falls back to `null` (not base64) if the upload fails. Base64 data URL is still used for immediate local strip preview. Added demo account guard.

---

### ~~P1-4~~ — Follower/following counts hardcoded ✅
**Fixed:** Three changes:
1. `loadProfileSettings()` — added `Promise.all` with three `head:true, count:'exact'` queries (followers, following, posts) that update `#followerCount`, `#followingCount`, `#postCount` on login for real users. Demo account keeps its hardcoded values.
2. `openFriendProfile()` — replaced sequential follow-state check with a `Promise.all` that runs follow check + follower count + following count + post count in parallel. Updates `#fpFollowers`, `#fpFollowing`, `#fpPostCount` once `fpCurrentProfileId` is resolved.
3. `toggleFriendFollow()` — added optimistic ±1 updates to `#followingCount` (own profile) and `#fpFollowers` (friend profile) on follow/unfollow, with rollback on Supabase error.

---

### ~~P1-5~~ — Multi-image posts only save first image ✅
**Fixed:** `submitPost()` now captures `filesToUpload` from all `selectedImages` before the async IIFE. Uploads all files in parallel via `Promise.all` with unique paths `{uid}/{timestamp}-{index}.{ext}`. Single image stored as plain URL string (backward compat); multiple images stored as `JSON.stringify(urls)` in the existing TEXT column — no migration needed. Added `parseImageUrls()` helper that handles both formats in the read path. `loadFeedFromSupabase()` now calls `parseImageUrls(p.image_url)` so carousels load correctly from Supabase.

---

### ~~P1-6~~ — Text-only posts blocked ✅
**Fixed:** Removed the hard image guard in `submitPost()`. Combined validation now only blocks if both caption and images are empty, showing a `showToast` instead of an `alert`. `firstExif` safely handles the no-image case with a `|| null` fallback. Text-only posts insert with `image_url: null`.

---

### ~~UI-01~~ — Post modal confirm button hidden behind bottom nav ✅
**Fixed:** Added `style="padding-bottom: 80px;"` to `#postModal .modal-sheet`. Tab bar is ~62px tall (z-index 355 over modal z-index 300); 80px bottom padding pushes the Share Post button 18px above the tab bar top.

---

### ~~UI-02~~ — Diary modal confirm button hidden behind bottom nav ✅
**Fixed:** Same fix — added `style="padding-bottom: 80px;"` to `#diaryModal .modal-sheet`. Done in the same pass as UI-01.

---

### ~~UI-04~~ — Duplicate collections strip on profile page ✅
**Fixed:** Removed the hardcoded "New" diary-item from `#profileDiariesStrip` (the old placeholder that was showing a second New button). Updated both `enterApp()` show/hide loops from `forEach((el, i) => { if (i > 0) ... })` to `forEach(el => { ... })` — index 0 was the removed New button; now all demo items start at index 0 so the index condition was wrong.

---

### ~~UI-06~~ — Tapping a user's name does not open their profile ✅
**Fixed:** Added `userId: p.user_id` to post objects in both `loadFeedFromSupabase()` and `subscribeFeedRealtime()`. In `buildPostCard()`, moved `isOwnPost`/`nameTappable`/`fpClick` computation before the pulse branch so both feed types share it — author name in the caption block and avatar are tappable when `post.userId` is set and it isn't the current user's own post; pulse-author div gets the same `fpClick`. Demo contacts fall back to `contactProfiles` check unchanged. Added `onclick="closeModal(...);openFriendProfile(...)"` to `.following-item` rows in `renderFollowersItems()` and `renderFollowingItems()` (demo mode) — real-user path already tappable via `renderFollowListFromSupabase()`.

---

### ~~UI-07~~ — Diary entries appearing in collections instead of feed strip ✅
**Fixed:** Audited both data paths — diary entries write `feed_type: 'diary'` and collections query only the `collections` table, so there was no actual data overlap. Root cause was visual: `#profileDiariesStrip` and `#collectionsStrip` were adjacent with no labels, both using identical diary-item circle UI. Added "Diary" section heading above `#profileDiariesStrip` and "Collections" heading above `#collectionsStrip` to clearly distinguish them.

---

### ~~UI-08~~ — Collections layout broken on profile page ✅
**Fixed:** Added `flex-wrap: nowrap` to the `#collectionsStrip` inline style so all items (including the New Collection button) stay in a single horizontal scrollable row. Combined with the "Collections" label added in UI-07, the strip is now visually correct.

---

### ~~UI-09~~ — Follower/post counts reset when switching tabs ✅
**Fixed:** `renderFeed()` and `renderProfileGallery()` were both overwriting `#postCount` from the in-memory `posts` array. For real users the feed only contains followed users' posts, so their own posts were typically absent — setting the count to 0 or very low and overwriting the authoritative count from `loadProfileSettings()`. Guarded both updates so they only run for the demo account.

---

### ~~UI-10~~ — News and Pulse feeds show personal feed content ✅
**Fixed:** Two root causes: (1) `fetchLiveNews()` referenced `isDemoAccount` which is a `const` local to `enterApp()` — inaccessible from this outer function, throwing a ReferenceError that prevented the personal-post hide logic from running. Fixed by replacing with `currentUser.name !== DEMO_ACCOUNT_NAME`. (2) `submitPost()` was not writing `feed_type` to Supabase, so all posts had NULL `feed_type` and were not filterable by mode. Fixed by adding `feed_type: 'personal'` to the insert payload. `setFeedMode()` already filters by `data-feed-type` attribute so Pulse correctly shows empty for real users until FEATURE-01 adds Pulse post creation.

---

## P2 — Important (needed for Phase 1, not immediately blocking)

### ~~P2-1~~ — Feed requires page refresh for new posts ✅
**Fixed:** Added `subscribeFeedRealtime(followedIds)` called from `loadFeedFromSupabase()` after resolving followed IDs. Creates a `postgres_changes` INSERT channel filtered to `user_id=in.(...)`. On new post: fetches the author's profile, builds a post object, prepends to `posts`, calls `renderFeed()`. Diary posts are filtered out. Channel is torn down and rebuilt on each feed reload, and cleaned up on `SIGNED_OUT`. `_feedRealtimeChannel` module-level var tracks the active channel.

---

### ~~P2-2~~ — Collections not persisted to Supabase ✅
**Fixed:** Added `<div id="collectionsStrip">` to profile HTML (was missing — `renderCollections()` was targeting a non-existent element). Updated `renderCollections()` to use array index for onclick (safe for UUID ids). Replaced stub `addCollection()` with async function that uses `prompt()` for name input, inserts to `collections` table, updates local id on response. Added `loadCollectionsFromSupabase()` called from `enterApp()` for non-demo users. Migration `005_collections.sql` creates `collections` and `collection_items` tables with RLS. ⚠️ Run migration in Supabase SQL editor.

---

### ~~P2-3~~ — No invite code system ✅
**Fixed:** Added `inviteCode` input field at the top of the register panel. `startRegistration()` validates the code against `invite_codes` table (checks it exists and `used_by IS NULL`) before calling `supabase.auth.signUp`. Code ID stored in `pendingReg.inviteCodeId`. After successful profile upsert in `finishRegistration()`, marks the code as used with `UPDATE ... SET used_by = userId, used_at = now() WHERE used_by IS NULL`. Migration `006_invite_codes.sql` creates the table with RLS and seeds 10 test codes (HATCH-ALPHA, HATCH-BETA1–5, etc.). ⚠️ Run migration in Supabase SQL editor.

---

### ~~P2-4~~ — Follow request flow not implemented ✅
**Fixed:** Extended `toggleFriendFollow()` with 4 cases: (1) unfollow if already following, (2) withdraw pending request, (3) instant follow for public accounts, (4) insert into `follow_requests` + notify target for private accounts. `openFriendProfile()` now fetches `privacy` from profiles and checks `follow_requests` for pending status alongside the existing follow/count queries — sets button to Following / Requested / Follow accordingly. Added `#followRequestsCard` section to `#tab-notifs` with Approve/Decline buttons. `loadNotificationsFromSupabase()` loads pending requests and DB notification rows on login; `approveFollowRequest()` inserts into follows, updates request status, notifies requester; `declineFollowRequest()` updates status to declined. Migrations `008_follow_requests.sql` and `009_notifications.sql` created. ⚠️ Run both migrations in Supabase SQL editor.

---

### ~~BUG-01~~ — Approve/Decline buttons not responding ✅
**Fixed:** `approveFollowRequest()` was inserting `{ follower_id: requesterId, following_id: currentUser.id }` but the `follows` RLS policy only permitted `follower_id = auth.uid()`. Since the approver is `following_id`, the insert was blocked. Migration `010_follows_approve_policy.sql` drops and recreates the policy with `auth.uid() = follower_id OR auth.uid() = following_id`. ⚠️ Run migration in Supabase SQL editor.

---

### ~~BUG-02~~ — Follow request appearing twice in notifications ✅
**Fixed:** `loadNotificationsFromSupabase()` was pushing all `notifRows` into the alerts array including `type === 'follow_request'` rows, which were already displayed in the Follow Requests card. Added `if (n.type === 'follow_request') return;` guard at the top of the `notifRows.forEach` loop.

---

### ~~P2-5~~ — Trusted Circles not persisted or created at onboarding ✅
**Fixed:** Migration `017_circles.sql` creates `circles` (id, user_id, name, created_at) and `circle_members` (id, circle_id, member_id, created_at) tables with RLS. `loadCirclesFromSupabase()` queries the circles table on login and replaces `groupDefs` with real DB rows for non-demo users. `renderGroupChipsInPostModal()` re-renders the audience picker group chips from live `groupDefs` after any circles change. `addNewGroup()`, `deleteCurrentGroup()`, and `saveCurrentGroup()` all persist to Supabase for real users with demo fallbacks. Default "Family" and "Close Friends" circles are seeded for every new account in `finishRegistration()`. Group manager shows an empty-state prompt for real users (no contacts array yet — member management is wired to `circle_members` in a follow-up once followed users are loaded into contacts).
---

### ~~SOCIAL-01~~ — Comments not working for real users ✅
**Fixed:** All `onclick` handlers in `buildPostCard()` (both pulse and main feed sections) and `renderProfileGallery()` now quote the post ID (`'${post.id}'`) so UUID strings are valid JS. `toggleComments()` calls `loadComments(postId)` whenever the section opens — this queries `comments` joined with `profiles(name, avatar_url)` and re-renders with real avatars/names. `addComment()` is now async: optimistically appends the comment, inserts into Supabase `comments` table, and rolls back (removes the item, restores the input) on error. `buildCommentHtml()` accepts `avatar_url` field. All Supabase writes guarded with demo account check. Works on both photo posts and pulse posts.

---

### ~~SOCIAL-02~~ — Likes not persisting ✅
**Fixed:** `toggleLike()` is now async with optimistic UI: flips the in-memory `liked`/`likes` state and updates the button immediately, then inserts or deletes from the `likes` table. Rolls back on error (ignores duplicate key `23505`). `loadLikesForFeed()` runs after `renderFeed()` in `loadFeedFromSupabase()` — parallel queries for all like counts and the current user's own likes, updates all visible like buttons. Fully guarded with demo account check.

---

### ~~SOCIAL-03~~ — Save post not persisting ✅
**Fixed:** `toggleSave()` is now async with optimistic UI: flips `saved` state and updates the bookmark icon immediately, then inserts or deletes from `saved_posts`. Rolls back on error. `loadSavedPostsForFeed()` runs after `renderFeed()` in `loadFeedFromSupabase()` — restores all saved states from DB. `loadSavedPostsForProfile()` queries `saved_posts` joined with `posts` and `profiles`, renders the profile Saved tab from Supabase for real users (grid or linear view). `setProfileContentTab()` calls `loadSavedPostsForProfile()` for real users when tab === 'saved'. Demo account falls back to in-memory `posts.filter(p => p.saved)` unchanged.

---

### ~~P2-6~~ — Feed not filtered by post audience ✅
**Fixed:** Migration `018_circle_member_lookup.sql` creates a `SECURITY DEFINER` RPC `get_circle_owners_for_member(member_uuid)` that returns the user_ids of all circle owners who have added the caller to one of their circles — bypassing the RLS policy that restricts `circle_members` reads to the circle owner only (a direct query would always return empty for the viewer). `loadFeedFromSupabase()` now calls this RPC after resolving followedIds and builds `_feedInCircleOf` (module-level Set). Posts query adds `user_id` to the SELECT (also fixes the latent UI-06 userId bug). Feed rows are client-side filtered: `visibility !== 'friends' || _feedInCircleOf.has(p.user_id)`. The realtime subscription handler applies the same guard on incoming INSERT events. ⚠️ Run migration `018_circle_member_lookup.sql` in Supabase SQL editor.

---

### ~~P2-7~~ — Diary/Memories not truly private ✅
**Fixed:** Changed diary insert in `submitDiaryEntry()` from `visibility: 'friends'` to `visibility: 'private'`. Also fixed the test helper insert. Migration `007_diary_private_rls.sql` adds an RLS SELECT policy on `posts` that permits access only when `feed_type != 'diary'` OR `user_id = auth.uid()`. ⚠️ Run migration in Supabase SQL editor.

---

### ~~UI-05~~ — Followers/following counts not tappable on profile ✅
**Fixed:** Extended `openFollowersModal(profileId)` and `openFollowingModal(profileId)` to accept an optional profileId. For real (non-demo) users both functions query Supabase (`follows` table with profiles FK join) and render tappable items via new `renderFollowListFromSupabase()` helper — each item calls `closeModal(); openFriendProfile()`. "Edit Groups" button hidden when viewing a friend's profile. Added `onclick="openFollowersModal(fpCurrentProfileId)"` / `onclick="openFollowingModal(fpCurrentProfileId)"` to friend profile stat divs. `filterFollowers` and `filterFollowing` guard against overwriting Supabase-loaded content (only run in demo mode when `contacts` is populated).

---

### ~~UI-03~~ — Diary entries not showing in feed strip ✅
**Fixed:** Added `loadFeedDiaries()` which queries own diary posts + followed users' diary posts from the last 24 hours, updates `currentUser.diary`, toggles the own ring's `unseen` class, and renders one circle per followed user (most recent entry, deduped). Called from `enterApp()` for non-demo users and from `submitDiaryEntry()` after a successful DB insert so new entries appear immediately without a refresh.

---

### ~~FOLLOW-02~~ — Follow requests only required for private accounts ✅
**Fixed:** Implemented as part of P2-4. `toggleFriendFollow()` checks `fpCurrentProfilePrivacy` (stored when `openFriendProfile()` loads the profile row). Public accounts follow instantly; private accounts go through the request flow.

---

### ~~P2-8~~ — Notifications not persisted to Supabase ✅
**Fixed:** Three changes completing the notifications pipeline:
1. **Mark as read on open** — when the Notifications tab is opened, a fire-and-forget `UPDATE notifications SET read=true WHERE user_id=me AND read=false` runs in Supabase. `loadNotificationsFromSupabase()` is also called on open so any new notifications received since login appear immediately without a page refresh.
2. **Event invite notifications** — the local-only `notifications.unshift()` on event creation is now guarded to demo mode only. For real users, after `event_invites` rows are inserted, a `notifications` insert writes one row per invitee (`type: 'event_invite'`, `actor_id: currentUser.id`).
3. **Follow request / approval** — already wired in P2-4: follow request sent writes `type:'follow_request'` to target; approval writes `type:'follow_approved'` to requester. `loadNotificationsFromSupabase()` was already called on login. No new migration needed — `notifications` table exists from migration 009.

---

### ~~FEATURE-01~~ — Pulse post creation ✅
**Fixed:** Replaced 4th speed dial item (availability/coordinate) with a Pulse button (waveform icon, `openPulseModal()`). Added `#pulsePostModal` with a 150-char textarea, live character counter (`updatePulseCounter()`), audience picker (Everyone=public / Circles=friends), and Post button. `_pulseAudience` module-level variable tracks selection. `submitPulsePost()` validates length, optimistically adds to `posts` array and re-renders, inserts to Supabase with `feed_type:'pulse'`, updates the in-memory post ID on success. Comments already work on Pulse posts from SOCIAL-01. Availability poll still accessible via the event creation modal.

---

### ~~PERF-01~~ — General loading performance ✅
**Fixed:** Two changes: (1) In `loadFeedFromSupabase()`, the circles RPC and posts query now run in parallel via `Promise.all` — previously they were sequential, adding a full round-trip before the feed appeared. (2) Added `showFeedSkeleton()` which injects 3 shimmer-animated placeholder cards into the feed immediately on login, replaced by real content when `renderFeed()` fires — eliminates the blank-screen gap. LIMIT was already 60. Supabase project is on free tier — cold-start latency is expected on first request after inactivity; no code fix possible for that.

---

### ~~UI-11~~ — Profile picture not consistent across the app ✅
**Fixed:** After a successful avatar upload, `uploadAvatarFile()` now also updates: (1) `#yourDiaryAvatar` (diary circle, was missing), and (2) any already-rendered feed cards for the user's own posts (updates `p.avatar` in-memory and swaps the `<img>` src in the DOM). Profile header (`#profilePic`) and `buildPostCard()` already referenced `currentUser.avatar` — no change needed there.

---

### ~~UI-12~~ — Event invite search not working for private events ✅
**Fixed:** `loadFollowersForPicker()` was already querying the `follows` table correctly. The missing piece was a search/filter UI. Added a live search input (`#inviteSearch`) above `#inviteCheckboxes` that calls `filterInviteList()` on each keystroke — shows/hides checkbox labels by name match. Input is cleared each time `openCreateEventModal()` is called. Selecting a checkbox adds the person to the invite list; the existing `submitNewEvent()` picks up all checked inputs.

---

### ~~UI-14~~ — Events calendar does not scroll to today's date on open ✅
**Fixed:** `calYear` and `calMonth` were hardcoded to `2026` and `2` (March). Replaced with `const _calNow = new Date(); let calYear = _calNow.getFullYear(), calMonth = _calNow.getMonth()`. The `.today` highlight CSS class was already applied by `renderCalendar()` — no further changes needed. Forward/back month navigation unchanged.

---

### ~~UI-13~~ — Event time picker minute should snap to 5-minute intervals ✅
**Fixed:** The time picker is a native `<input type="time">` (not a custom clock dial). Added `step="300"` (300 seconds = 5 minutes) to both `#eventTime` and `#eventEndTime` inputs so the browser's native picker snaps to 5-minute intervals. Added a `snapMin()` helper in `submitNewEvent()` as a safety net that rounds any typed-in value to the nearest 5 minutes (`Math.round(m / 5) * 5`) and handles the 60-minute rollover edge case. Hours are unaffected.

---

## P3 — Defer (build after initial user testing)

### P3-1 — KYC video verification is a fake UI
**What:** `startRecording()` is a fake timer — no `getUserMedia`, no `MediaRecorder`. `submitVerification()` sets an in-memory flag only. No video is captured or uploaded.
**Fix:**
1. Replace fake timer with real `getUserMedia` + `MediaRecorder` implementation
2. Upload recorded video blob to a private `kyc-videos` Supabase Storage bucket
3. Add `verified` column migration to `public.profiles`
4. Update `profiles.verified = true` on successful upload
**Effort:** Large

---

### P3-2 — Verified badge is hardcoded to demo profile
**What:** Verified badge HTML at L2855 is hardcoded to the demo profile. No dynamic check against Supabase.
**Fix:** On profile load, check `profiles.verified`. Show badge only when `true`. Depends on P3-1 adding the `verified` column.
**Effort:** Medium

---

### P3-3 — Video post creation not built
**What:** No video upload path exists. Create menu has no video option.
**Fix:** Add video option to create menu. Implement video file selection, upload to Supabase Storage `posts` bucket, store public URL in post record.
**Effort:** Large

---

### P3-4 — Algorithm dial is a tab strip not a real dial
**What:** Feed mode is a tab strip (Explore/Personal/News/Pulse) not the chronological ↔ suggested slider described in the roadmap. News and Pulse modes rely on demo data.
**Fix:** Replace tab strip with a real-time slider. Connect slider position to feed sort order and filtering. Persist preference to `profiles` or localStorage.
**Effort:** Medium

---

## Completed

- [x] AUTH-01 — Avatar upload prompt timing fix: `_pendingNewUserMsg` moved before `await signInWithPassword()` in `finishRegistration()` so `onAuthStateChange` sees it when it fires synchronously inside Supabase's signIn
- [x] Search returning results (migration 003 applied)
- [x] Friend profile layout matches own profile layout
- [x] Bottom nav visible on friend profile
- [x] Friend profile sub-nav (Posts / Pulse / Tagged)
- [x] Follow button text displaying correctly
- [x] Sub-nav positioning fixed
- [x] News feed BBC/Guardian only showing for followed outlets (demo)
- [x] NEWS-01 — Real news feed via outlet accounts + RSS poller: migrations 019 (outlet profiles + account_type) and 020 (external_url on posts); api/fetch-news.js serverless function polls BBC and Guardian RSS hourly via vercel.json cron; fetchLiveNews() for real users queries outlet posts from Supabase; "Read full article ↗" link on news cards; openArticle() updated to handle DB posts (no longer requires post.article). ⚠️ Run migrations 019 and 020 in Supabase SQL editor. ⚠️ Set SUPABASE_URL, SUPABASE_SERVICE_KEY, CRON_SECRET in Vercel env vars.
- [x] `openChatFromProfile()` function completed
- [x] Profile name backfilled for existing users
- [x] Avatar upload working (uploads to avatars bucket, writes avatar_url to profiles)
- [x] Profile name/bio editing persisted to Supabase
- [x] Sign up / sign in / sign out working
- [x] Password reset working (sendResetLink calls resetPasswordForEmail)
- [x] Avatar upload prompt shown post signup (900ms delay for new non-demo users)
- [x] Feed loads from followed users only (loadFeedFromSupabase filters by follows table)
- [x] Feed ordered chronologically (created_at descending)
- [x] Demo data gated correctly (isDemoAccount guard clears all demo arrays)
- [x] Follow/unfollow persisted to Supabase follows table
