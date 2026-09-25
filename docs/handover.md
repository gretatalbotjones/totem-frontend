# Handover

**This file is the single source of truth for a new Claude session. Read this first, then read only what you need.**

---

## What this project is

**Hatch** — privacy-first social platform for urban 25–40s. UK-first (East London launch). No data selling, no algorithmic feed, KYC-verified real identities, user-controlled audiences.

Live at: **https://totem-frontend-five.vercel.app/**
Repo: `gretatalbotjones/totem-frontend` (GitHub, auto-deploys to Vercel on push to `main`)

**Current form:** Single `index.html` prototype (~10,800 lines). Supabase backend. This is intentional — it's a working product specification, not bad engineering. A Next.js migration is planned but not started.

---

## Completed (what works)

- Auth: signup (invite code + email OTP), login, password reset, logout
- Personal feed: followed users only, chronological, Supabase-backed, realtime new posts
- Post creation: photo (single + multi-image carousel), text, pulse (≤150 chars), diary
- Audience filtering: friends-only posts correctly hidden from non-circle-members
- Follow graph: instant (public accounts) + request flow (private accounts) + approve/decline
- Trusted Circles: Supabase-persisted, seeded at registration, audience picker wired
- Notifications: follow request, follow approved, event invite — all in DB, marked read on open
- Own profile + friend profiles: load from Supabase, post grid, avatar upload (syncs everywhere)
- Events calendar: month + week, opens on today's date, RSVP, invite search
- News feed: BBC and Guardian as outlet accounts, RSS-ingested articles, follow-gated
- Search: finds real users by name via Supabase ilike
- Collections: create + load from Supabase
- All 20 Supabase migrations applied
- Test suite: 39 tests, 36 pass, 0 fail (run: `node tests/supabase_test_suite.js`)
- Documentation suite: `docs/` folder (product, strategy, design, features, architecture, migration, handover)

---

## Current state

**The prototype is stable and live.** No critical bugs blocking real users from core flows.

Last significant changes (Aug 2026):
- Fixed `showFeedSkeleton()` destroying `#emptyMsg` (was inside `#feed`, `innerHTML` assignment wiped it)
- Fixed friend profile gallery — was showing "No posts yet" for all real users (was reading demo `contactPosts` only)
- Added FEATURE-01 (Pulse posts), PERF-01 (parallel feed queries + skeleton), UI-11 (avatar sync), UI-12 (invite search)
- Added news feed: outlet accounts (migration 019), `external_url` column (migration 020), `api/fetch-news.js` serverless function

---

## Known issues

| Issue | Severity | Description | Fix approach |
|---|---|---|---|
| Invite-only event RLS | High | Invitees can't see event details even after being invited. RLS policy `events: invitees read` only allows `auth.uid() = user_id` (owner). A new policy like `id IN (SELECT event_id FROM event_invites WHERE invitee_id = auth.uid())` is needed — but referencing `event_invites` from `events` policy caused infinite recursion previously. | New migration needed. Use `security definer` function or restructure policy. |
| Circle member management | Medium | UI to add followed users to circles is incomplete. The `circle_members` table and RLS exist, but the group manager picker doesn't load followed users — it shows the demo `contacts` array only. | In `index.html`: `loadCirclesFromSupabase()` sets `groupDefs` but members stay empty. Need to load `circle_members` rows and match to followed users. |
| KYC fake UI | Medium | Video verification step in registration is a fake timer with no camera access. `submitVerification()` sets an in-memory flag only. | P3 item: replace with Onfido SDK. Requires commercial decision (Onfido account). |
| News cron not automated | Low | `api/fetch-news.js` must be triggered manually — Vercel cron requires Pro plan. | Manual: `curl -H "Authorization: Bearer hatch-cron-2026-secret-xyz" https://totem-frontend-five.vercel.app/api/fetch-news`. Or upgrade Vercel plan. Or use cron-job.org. |
| Diary 24-hour expiry missing | Low | Diary posts persist indefinitely. No deletion mechanism exists. | Needs pg_cron on Supabase or a scheduled Vercel function. |
| Tagged tab shows nothing | Low | Profile "Tagged" tab shows "No tagged posts yet" for all real users. Tags are not stored to Supabase. | Would need a Supabase query for posts where `tagged_people` includes the user ID — or a separate `post_tags` table. |
| Share post does nothing | Low | "Share" button on posts has no real implementation. | Minor — low priority. |

---

## Recommended next task

**Option A (quick win — 1–2 hours):** Fix the invite-only event RLS bug. This is blocking users from seeing events they've been invited to. Requires a new migration. Approach: create a `SECURITY DEFINER` function `is_event_invitee(event_uuid UUID)` that checks `event_invites` without RLS, then add an `events: invitees read` policy using it. Migration goes in `supabase/migrations/021_fix_event_invitees_rls.sql`.

**Option B (medium — half day):** Fix circle member management. In `openGroupManager()` (search index.html), when `fpCurrentProfileId` resolves, also call a function to load followed users and show which are in the current circle. Requires updating the group manager UI to show followed users as a checklist.

**Option C (large):** Begin Next.js migration. See `docs/migration-plan.md` Phase 0.

**Confirm with Greta** which path to take before starting.

---

## Files most likely to change

| File | Why |
|---|---|
| `index.html` | All prototype feature work happens here |
| `supabase/migrations/` | Any schema change needs a new numbered migration |
| `api/fetch-news.js` | News ingestion logic |
| `docs/handover.md` | Update at end of every session |
| `docs/feature-inventory.md` | Update status when features change |
| `TASKS.md` | Legacy backlog — still useful for history but docs/ is now the primary reference |

---

## Risks

| Risk | Likelihood | Impact | Note |
|---|---|---|---|
| JS parse error crashes entire app | Medium | Critical | Has happened twice. Always run a syntax check after editing index.html. Previous cause: duplicate `const` in same scope. |
| Demo data leaking to real users | Low | Critical | The `isDemoAccount` guard must be on every Supabase write and every piece of demo data rendering. Never remove without replacing. |
| Supabase RLS regression | Low | High | After any migration, run `node tests/supabase_test_suite.js` to confirm no breakage. |
| Vercel webhook stops triggering | Medium | High | Has happened. Fix: Vercel → Settings → Git → Disconnect and reconnect the GitHub repo. |
| `vercel.json` crons block deployment | High if added | Critical | Happened in Aug 2026 — adding `crons` to vercel.json silently blocked all deployments (Hobby plan). Do NOT add `crons` to vercel.json unless on Pro plan. |
| News articles stop appearing | Low | Medium | Manual trigger: `curl -H "Authorization: Bearer hatch-cron-2026-secret-xyz" https://totem-frontend-five.vercel.app/api/fetch-news` |

---

## Key constants (never hardcode elsewhere)

```
Supabase URL:      https://ocztxpmmbopcbtshetts.supabase.co
Supabase anon key: sb_publishable_QcqD9p8Wk8zHRV-dsSQ4Xw_bVkdC2fy  (in index.html)
BBC News UUID:     a0000000-0000-0000-0000-000000000001
Guardian UUID:     a0000000-0000-0000-0000-000000000002
Demo account:      greta.talbot.jones@gmail.com / "Greta Talbot-Jones"
CRON_SECRET:       hatch-cron-2026-secret-xyz  (in Vercel env vars only, not in git)
```

---

## How to start a session

1. Read this file
2. Run `node tests/supabase_test_suite.js` — confirm 36 pass, 0 fail
3. Take a timestamped backup: `cp index.html backups/index_backup_$(date +%Y%m%d_%H%M).html`
4. Do the work
5. Take another backup
6. Run tests again
7. Commit: `git add -p && git commit -m "..."  && git push origin main`
8. Update this file with what changed and what the next task is

## How to end a session

- Update `docs/handover.md` — Completed section, Known Issues, Recommended Next Task
- Update `docs/feature-inventory.md` if any feature status changed
- Commit and push all changes including docs

---

## Document index

| File | Purpose |
|---|---|
| `docs/product.md` | Mission, user journeys, MVP definition, success criteria |
| `docs/strategy.md` | Growth plan, market sizing, revenue model, funding, competition |
| `docs/design-principles.md` | Visual rules, UX principles, anti-patterns, emotional goals |
| `docs/feature-inventory.md` | Every feature with working/buggy/partial/broken status |
| `docs/architecture.md` | Current and target architecture, DB schema, auth, deployment |
| `docs/migration-plan.md` | Next.js migration phases, blockers, next actions |
| `docs/handover.md` | This file — operational context for a new session |
| `CLAUDE.md` | Original session instructions and schema reference (legacy) |
| `TASKS.md` | Completed backlog — historical record of what was built and why |
