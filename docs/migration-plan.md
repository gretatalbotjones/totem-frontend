# Hatch — Migration Plan

## Guiding principles

1. **Never big-bang.** Each phase ships something real users can test.
2. **Supabase is stable.** The database, auth, storage and all migrations carry forward unchanged. Only the frontend changes.
3. **index.html is the spec.** Treat every screen and interaction as a reference. Rebuild logic, not code.
4. **No demo data in production.** The Next.js app has real users only. Remove all `_DEMO_*` arrays and `isDemoAccount` guards.
5. **TypeScript from day one.** No `any`. Supabase-generated types for all DB queries.
6. **Test before moving on.** Each phase requires manual testing of the golden path before the next phase starts.

---

## Phase 0 — Project setup (1–2 days)

**Goal:** Runnable empty Next.js app deployed to Vercel.

Tasks:
- [ ] Create new Next.js 14 project with App Router + TypeScript + Tailwind
- [ ] Configure Tailwind with Hatch design tokens (copy from `docs/design-principles.md`)
- [ ] Add Supabase dependencies (`@supabase/supabase-js`, `@supabase/ssr`)
- [ ] Create `lib/supabase/client.ts` and `lib/supabase/server.ts`
- [ ] Run `supabase gen types typescript` → `lib/supabase/types.ts`
- [ ] Set up Vercel project, connect GitHub, configure environment variables
- [ ] Add `middleware.ts` — protect `(app)` routes, redirect unauthenticated users to `/login`
- [ ] Add root `app/layout.tsx` with Zustand provider
- [ ] Create `store/useAppStore.ts` (user, toasts, modal state)
- [ ] Deploy empty app to Vercel — confirm auth redirect works

**Definition of done:** `/login` renders, unauthenticated users hitting `/feed` redirect to `/login`.

---

## Phase 1 — Auth flows (3–5 days)

**Goal:** Real users can sign up, log in, and reach an empty feed.

Screens:
- `/login` — email + password, "Continue as" returning user row
- `/register` — invite code + name + email + password (3-step: account → OTP → KYC stub)
- `/verify` — KYC stub (skip button, real Onfido integration is Phase 5)
- Password reset flow (URL-based, PKCE)

Key components:
- `components/ui/AuthCard.tsx`
- `components/auth/LoginForm.tsx`
- `components/auth/RegisterForm.tsx`
- `components/auth/OTPInput.tsx`

Key hooks/utils:
- `lib/hooks/useUser.ts` — current user from Supabase session
- Auth actions in server actions or API routes

Reference: `index.html` auth cards (`authCard-start`, `authCard-otp`, `authCard-video`, `forgotCard`).

**Definition of done:** New user can register with invite code, verify email OTP, reach `/feed`. Existing user can log in. Password reset works.

---

## Phase 2 — Feed (5–7 days)

**Goal:** Core feed working. This is the product's beating heart.

Screens:
- `/feed` — home feed with sub-nav and skeleton loading

Components:
- `components/feed/Feed.tsx` — infinite/windowed scroll, realtime subscription
- `components/feed/PostCard.tsx` — photo, pulse, news variants
- `components/feed/FeedSubNav.tsx` — Personal / Pulse / News / Explore tabs
- `components/feed/DiaryStrip.tsx` — diary rings
- `components/ui/BottomNav.tsx` + `components/ui/TopNav.tsx`
- `components/ui/Skeleton.tsx` — shimmer cards

Hooks:
- `lib/hooks/useFeed.ts` — follows lookup, circle membership, posts query, realtime sub

**Order of implementation within Phase 2:**
1. Shell layout (TopNav + BottomNav + tab-page structure)
2. PostCard component (photo variant first)
3. Feed query + skeleton
4. Realtime subscription
5. Pulse + News variants
6. DiaryStrip
7. Explore / algorithm dial

**Definition of done:** Real user sees their followed users' posts in chronological order. New posts appear without refresh. News tab shows articles if following BBC/Guardian.

---

## Phase 3 — Post creation (3–4 days)

**Goal:** Users can create and publish content.

Components:
- `components/post/CreatePostModal.tsx` — photo + caption + audience
- `components/post/CreatePulseModal.tsx` — 150-char text
- `components/post/AudiencePicker.tsx` — Everyone / Circles
- `components/post/ImageUpload.tsx` — multi-image, carousel preview
- `components/diary/CreateDiaryModal.tsx` — diary entry
- Speed dial (FAB) with 4 options: Diary / Photo / Pulse / Event

Reference: `openPostModal()`, `openPulseModal()`, `openDiaryModal()` in `index.html`.

**Definition of done:** User can create a photo post, pulse post, and diary entry. Posts appear in feed immediately (optimistic).

---

## Phase 4 — Profile + follow graph (4–6 days)

**Goal:** Own profile, friend profiles, and the complete follow experience.

Screens:
- `/profile` — own profile
- `/profile/[id]` — any user's profile (or outlet)

Components:
- `components/profile/ProfileHeader.tsx`
- `components/profile/ProfileGrid.tsx` — Photos/Pulse/Tagged/Saved tabs
- `components/profile/AvatarUpload.tsx`
- `components/profile/FollowersModal.tsx` / `FollowingModal.tsx`
- `components/circles/CircleManager.tsx`

Follow flow:
- Instant follow for public accounts
- Request → approve/decline for private accounts
- Notifications for follow events

**Definition of done:** User can view own and others' profiles. Follow/unfollow works. Follow request flow works end-to-end.

---

## Phase 5 — Events (3–4 days)

**Goal:** Events calendar fully functional.

Screens:
- `/events` — calendar + events list

Components:
- `components/events/Calendar.tsx` — month + week views, opens on today
- `components/events/EventCard.tsx` — RSVP, host vs invitee views
- `components/events/CreateEventModal.tsx` — with invite search

**Definition of done:** User can create an event, invite followers, RSVP to received invites. Calendar shows correct month with event dots.

---

## Phase 6 — Notifications + search (2–3 days)

**Goal:** All notification types working; user search functional.

Screens:
- `/notifications` — follow requests card + notification list
- Search overlay (global, in TopNav)

**Definition of done:** Follow request notification shows on open. Event invite notification shows. Search finds real users by name.

---

## Phase 7 — Collections + settings (2–3 days)

**Goal:** Collections and user settings.

- Collections strip on profile
- Create/manage collections
- Privacy settings
- Account deletion (GDPR)

---

## Phase 8 — KYC (Onfido) (3–5 days)

**Goal:** Real identity verification at signup.

- Integrate Onfido JavaScript SDK in `/verify`
- Vercel API route `/api/onfido/webhook` → set `profiles.verified = true`
- Show verified badge dynamically (not hardcoded)
- Remove fake `toggleRecording()` / `submitVerification()` implementation

**Note:** Requires Onfido account (sandbox available free, £1–3/check in production).

---

## Phase 9 — Performance + polish (ongoing)

- Image optimisation via Next.js Image component
- React Server Components for public content (profile pages, news articles)
- Prefetching (profile on hover, etc.)
- Error boundaries
- Accessibility audit (ARIA labels, focus management, colour contrast)
- Loading state consistency

---

## What to discard during migration

| Prototype element | Reason to discard |
|---|---|
| All `_DEMO_*` arrays | No demo mode in production app |
| `isDemoAccount` guards | No demo mode |
| `contactProfiles` + `contactPosts` | Demo-only in-memory state |
| `openSearchedProfile()` pattern | Replaced by proper routing |
| AI assistant (`processAIMessage`) | Not a real AI — drop entirely or replace with real LLM |
| `toggleRecording()` / fake KYC | Replaced by Onfido SDK |
| `liveNewsNextId` integer IDs | All IDs are UUIDs from Supabase |
| `backups/` folder | Git history replaces manual backups |
| EXIFR library | Keep if desired, but make it optional |
| `debug_script.js`, `mvp_test.mjs` | Development artefacts, not needed in prod |

---

## Migration risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Auth session mismatch between old and new app | Medium | Both use same Supabase project — sessions are transferable. Test with existing accounts. |
| RLS policies break in new fetch patterns | Low | Same Supabase client, same JWT. Run test suite after each phase. |
| Demo users hitting production with no data | Low | Remove all demo guards; new app is real-users-only from day one. |
| Onfido pricing surprises | Medium | Use sandbox for all development; only enable production on go-live. |
| Vercel Pro required for crons | Medium | Manual trigger via curl works for now; upgrade when needed. |
| Mobile feel lost in Next.js | Medium | Maintain mobile-first design. Test on real device every phase. |

---

## Timeline estimate

| Phase | Estimate | Cumulative |
|---|---|---|
| 0 — Setup | 1–2 days | 2 days |
| 1 — Auth | 3–5 days | 1 week |
| 2 — Feed | 5–7 days | 2.5 weeks |
| 3 — Post creation | 3–4 days | 3.5 weeks |
| 4 — Profile + follows | 4–6 days | 5 weeks |
| 5 — Events | 3–4 days | 6.5 weeks |
| 6 — Notifications + search | 2–3 days | 7.5 weeks |
| 7 — Collections + settings | 2–3 days | 8.5 weeks |
| 8 — KYC (Onfido) | 3–5 days | 10 weeks |
| 9 — Polish | Ongoing | — |

Realistic timeline with 1 full-time engineer: **10–12 weeks to feature parity with prototype**.
