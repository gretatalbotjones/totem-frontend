# Migration Plan

## Current phase

**Phase 0 — Prototype maintenance**

The single `index.html` prototype is live and in active use. The Next.js migration has not started. All work is currently on the prototype.

**Migration progress: 0%**

---

## Completed (prototype work)

All items below are done and live in production.

- ✅ Auth: login, signup with invite code, email OTP, password reset, session persistence
- ✅ Personal feed: followed users only, chronological, Supabase-backed, realtime
- ✅ Post creation: photo (single + carousel), text-only, pulse
- ✅ Audience filtering: friends-only posts hidden from non-circle-members (P2-6, migration 018 RPC)
- ✅ Follow graph: instant follow (public) + request flow (private) + approve/decline
- ✅ Trusted Circles: persisted to Supabase, default circles seeded at registration
- ✅ Notifications: follow request, follow approved, event invite — all persisted
- ✅ Profile page: own + friend profiles load from Supabase; avatar upload syncs everywhere
- ✅ Events calendar: month + week view, opens on today, RSVP, invite search
- ✅ News feed: BBC and Guardian outlet accounts, RSS ingestion via serverless function
- ✅ Collections: create and load from Supabase
- ✅ Search: user search via Supabase ilike
- ✅ Diary: create entry, feed strip, profile strip
- ✅ All 20 Supabase migrations applied
- ✅ Documentation suite: docs/ folder with 6 files

---

## In progress

Nothing formally in progress. Prototype is stable.

---

## Blocked

| Blocker | What it blocks | Resolution |
|---|---|---|
| Vercel Pro plan | Auto-cron for news ingestion | Upgrade plan OR use cron-job.org with manual HTTP trigger |
| Onfido account | Real KYC implementation | Requires commercial decision — use sandbox to develop, production to launch |
| Circle member management UI | Adding people to circles from followed list | UI work in index.html or tackle in Next.js migration |
| Invite-only event RLS | Invitees cannot see event details | SQL migration needed — see Known Issues in handover.md |

---

## Next actions (choose one path)

### Path A — Continue improving the prototype

Focus on the highest-value remaining bugs and missing features before migrating.

Recommended order:
1. **Fix invite-only event RLS** — invitees blocked from seeing event details (SQL fix, 1 hour)
2. **Circle member management** — add UI to add followed users to circles (index.html, medium)
3. **Real KYC (Onfido)** — replace fake video UI with Onfido SDK (large, needs Onfido account)
4. **Diary 24-hour expiry** — pg_cron or Vercel cron to delete expired posts
5. **Messages tab** — wire chat to Supabase realtime (large, Phase 2)

### Path B — Begin Next.js migration

Start fresh with a new Next.js project. Use index.html as specification only.

Phase 0 (1–2 days): New Next.js 14 project, Tailwind with Hatch tokens, Supabase client, middleware, empty deploy.

Full phase breakdown in the original migration-plan.md (archived below).

**Decision needed:** Confirm with Greta whether to fix remaining prototype bugs first, or start the Next.js migration.

---

## Migration phases (not yet started)

| Phase | Goal | Est. duration | Status |
|---|---|---|---|
| 0 | Next.js project setup + deploy | 1–2 days | Not started |
| 1 | Auth flows (login, register, KYC stub) | 3–5 days | Not started |
| 2 | Feed (core + realtime + skeleton) | 5–7 days | Not started |
| 3 | Post creation (photo, pulse, diary) | 3–4 days | Not started |
| 4 | Profile + follow graph | 4–6 days | Not started |
| 5 | Events calendar | 3–4 days | Not started |
| 6 | Notifications + search | 2–3 days | Not started |
| 7 | Collections + settings | 2–3 days | Not started |
| 8 | KYC (Onfido) | 3–5 days | Not started |
| 9 | Performance + polish | Ongoing | Not started |

**Estimated total:** 10–12 weeks to feature parity with prototype, 1 full-time engineer.

---

## Migration principles

1. **Supabase is unchanged** — same project, same URL, same keys, same schema
2. **index.html is the spec** — copy the logic, not the code
3. **No demo data** — real users only; remove all `_DEMO_*` arrays and `isDemoAccount` guards
4. **TypeScript from day one** — run `supabase gen types typescript` to get typed schema
5. **Nothing from free to paid** — this rule applies to the Next.js app too

---

## What to discard in migration

- All `_DEMO_*` arrays and `isDemoAccount` guards
- `contactProfiles`, `contactPosts` in-memory demo state
- `liveNewsNextId` integer IDs (all IDs are UUIDs in Next.js app)
- Fake `toggleRecording()` / KYC timer
- AI assistant (`processAIMessage`) — pattern-matched only, drop or replace with real LLM
- `backups/` folder — git history replaces manual backups
- `debug_script.js`, `mvp_test.mjs` — dev artefacts
