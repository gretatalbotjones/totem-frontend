# Hatch — Session Handover

---

## Session: 2026-09-25 — Repository Audit + Documentation

### What was done

This session performed a full repository audit and created the `docs/` documentation suite. **No code was changed.** The prototype (`index.html`) is exactly as it was at the end of the previous session.

### Files created

```
docs/product.md           — Product vision, feature overview, infrastructure summary
docs/design-principles.md — Colour tokens, typography, UI patterns, component mapping
docs/feature-inventory.md — Every feature with status (✅ / ⚠️ / 🔲 / ❌)
docs/architecture.md      — Current single-file architecture + target Next.js architecture
docs/migration-plan.md    — 9-phase incremental migration plan with estimates
docs/handover.md          — This file
```

---

## Current state of the prototype

### Deployment
- Live at: https://totem-frontend-five.vercel.app/
- GitHub: `gretatalbotjones/totem-frontend` (main branch, auto-deploys)
- Last commit: `264617c` — Fix showFeedSkeleton destroying #emptyMsg

### Test suite
- 39 tests: 36 pass, 0 fail, 3 skip (3 skips need `TEST_USER_2_ID` env var to enable)
- Run with: `node tests/supabase_test_suite.js`

### Known issues at end of last session
- **showFeedSkeleton bug** — Fixed in last commit. The skeleton was destroying `#emptyMsg` (a child of `#feed`) via `innerHTML` assignment. Fixed by preserving and re-appending `#emptyMsg`.
- **Friend profile gallery** — Fixed in `e7b80ad`. Was showing "No posts yet" for all real users because `renderFriendGallery()` only read `contactPosts` (demo array). Now calls `loadFriendPostsFromSupabase()`.
- **Vercel cron disabled** — `vercel.json` removed because crons require Vercel Pro plan. News articles must be fetched manually: `curl -H "Authorization: Bearer hatch-cron-2026-secret-xyz" https://totem-frontend-five.vercel.app/api/fetch-news`

### Pending Supabase migrations
All 20 migrations (001–020) have been applied in the Supabase SQL editor. Nothing pending.

### Environment variables (all set in Vercel)
- `SUPABASE_URL` — `https://ocztxpmmbopcbtshetts.supabase.co`
- `SUPABASE_SERVICE_KEY` — service_role key (in Vercel env vars)
- `CRON_SECRET` — `hatch-cron-2026-secret-xyz`

---

## Repository structure summary

```
totem-frontend/
├── index.html                    # Entire prototype (~10,800 lines)
├── api/fetch-news.js             # News RSS ingestion serverless function
├── supabase/migrations/          # 20 SQL migrations (all applied)
├── tests/supabase_test_suite.js  # Test suite
├── events_pipeline/              # Venue event scraper (not deployed)
├── docs/                         # Documentation (created this session)
├── CLAUDE.md                     # Session instructions + schema reference
├── TASKS.md                      # Completed backlog
├── KNOWN_ISSUES.md               # Issue log
├── NEXTJS_ARCHITECTURE.md        # Earlier architecture proposal (reference)
├── package.json                  # `commonjs` type, @supabase/supabase-js dep
└── backups/                      # Timestamped HTML backups (not committed)
```

---

## What the next session should do

### If continuing on the prototype

Priority bugs/features remaining in `index.html`:

1. **Circle member management** — UI for adding followed users to circles is incomplete. `circle_members` table exists but the picker in the Circles Manager doesn't populate from `follows`.

2. **Tagged tab on profile** — Shows "No tagged posts yet" for all real users. Needs a Supabase query for posts where the user is tagged.

3. **Availability polling → Supabase** — `openAvailabilityModal()` flow has UI but no backend connection.

4. **24-hour diary expiry** — Diary posts have no deletion mechanism. Need either a pg_cron job or a Vercel cron (requires Pro).

5. **Messages tab** — Currently demo-only (`_DEMO_CONTACTS`, `chatHistory`). Would need a Supabase `messages` table and realtime subscription.

6. **Event invite visibility** — Private/invite-only events: the RLS policy on `events` restricts invite-only events to the owner only (`auth.uid() = user_id`). Invitees can't read event details even after being invited. Migration needed.

### If starting the Next.js migration

Begin with **Phase 0** from `docs/migration-plan.md`:
- Create new Next.js 14 project (separate repo, e.g. `hatch-web`)
- Configure Tailwind with Hatch design tokens from `docs/design-principles.md`
- Connect to the **same Supabase project** (same URL, same keys)
- Run `supabase gen types typescript` to generate typed DB schema
- Deploy empty app to Vercel

The `index.html` prototype stays live for reference throughout the migration. Do not delete it until the Next.js app reaches full feature parity.

---

## Key decisions outstanding

1. **Monorepo vs separate repos** — If a React Native mobile app is planned soon, a Turborepo monorepo (`apps/web`, `apps/mobile`, `packages/shared`) makes sense from day one. Otherwise separate repos is simpler.

2. **Onfido vs Sumsub for KYC** — Both are strong. Onfido is more widely documented; Sumsub has aggressive startup pricing. Compare before committing.

3. **Vercel Pro plan** — Required for automatic news cron. Currently articles must be manually triggered. Upgrade when ready.

4. **`profiles.handle` column** — A unique, URL-safe handle (e.g. `HAT-XXXXXX` or `@username`) is needed for profile URLs in Next.js (`/profile/jack-farrant`). Not yet added to schema.

5. **Demo account future** — The prototype has a hardcoded demo account (`greta.talbot.jones@gmail.com`) for showing investors. The Next.js app should not have this pattern. Consider a separate Storybook or Figma prototype for demos.

---

## Notes on the existing codebase quality

The prototype has accumulated significant complexity but the **Supabase schema is clean and well-designed**. The 20 migrations are careful, idempotent, and well-commented. The RLS policies are correct (the one known issue being the events invitee visibility, noted above).

The JavaScript, while untyped and architecturally flat, is consistently organised by feature area and follows established conventions (`console.warn('[Hatch] ...')`, Supabase guards, demo account checks). The comments in `TASKS.md` are an excellent record of decisions made.

The design is visually coherent and the design tokens are well-defined. Moving them to Tailwind config will be straightforward.

**Bottom line:** The data layer is solid. The UI layer needs a rebuild. The product itself is well-thought-out.
