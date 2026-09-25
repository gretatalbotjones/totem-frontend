# Product

## Mission

Give people a private, honest, algorithm-free place to share with the people they actually know. No data selling. No behavioural manipulation. Verified real identities only.

*"Your content. Your rules."*

---

## Target users

**Primary:** Urban professionals, 25–40, UK-first (East London launch). Privacy-aware but not paranoid. Active on Instagram or WhatsApp but increasingly uncomfortable with it. Social plans with real-world friends are a core weekly behaviour.

**Not:** Teenagers, content creators seeking reach, brands, anonymous communities.

**Key insight:** 60–70% of Europeans report concern about data privacy but only 3–5% have switched away from Meta. The gap is supply-constrained (no good alternative), not demand-constrained. Hatch is the alternative.

---

## Core user journeys

### 1. Sign up
Invited by a friend → enter invite code → name + email + password → email OTP → video identity check (KYC) → prompted to upload avatar → land on empty personal feed with prompt to follow people.

**Current state:** Invite code, OTP, and avatar prompt all work. KYC step is a fake UI — user sees a recording button but no real camera capture happens.

### 2. Post something
Tap + in bottom nav → choose Diary / Photo / Pulse / Event → compose → pick audience (Everyone / Circles / Event attendees) → post. New post appears in feed immediately (optimistic).

**Current state:** Photo posts, pulse posts, and diary entries all work and persist to Supabase. Multi-image carousel works. Audience picker is wired — friends-only posts are filtered correctly in the feed.

### 3. Follow someone
Search by name → tap result → opens their profile → tap Follow. Public accounts follow instantly. Private accounts: request sent → they approve/decline → notification both ways.

**Current state:** Working end-to-end including follow requests, notifications, and follower/following counts.

### 4. See the news
Tap News sub-tab in feed → see articles from BBC News and The Guardian (if following either account). Tap an article → "Read full article ↗" opens original URL in new tab.

**Current state:** Working. BBC and Guardian are real outlet accounts in Supabase. Articles ingested via serverless RSS poller. Must be triggered manually (no auto-cron yet — requires Vercel Pro).

### 5. Plan an event
Tap + → Event → fill in details → set visibility (public / followers / invite-only) → create. Calendar updates. Invited friends receive a notification and can RSVP.

**Current state:** Event creation and calendar work. Invite-only event visibility has an RLS bug — invited users can't see event details even after being invited.

---

## MVP definition

The MVP is the prototype currently live at https://totem-frontend-five.vercel.app/

It includes: auth, personal feed, post creation (photo + pulse + diary), follow graph with request flow, Trusted Circles (audience filtering), events calendar, notifications, profile pages, news feed (BBC + Guardian), search, collections.

**What MVP does not include (deferred):**
- Real KYC (fake UI only)
- Messaging (demo data only, no Supabase connection)
- Diary 24-hour expiry (posts persist indefinitely)
- Circle member management UI (table exists, picker incomplete)
- Availability polling to Supabase (UI only)

---

## Success criteria

### Prototype (now)
- [ ] A new real user can sign up, post, follow someone, and see their posts in feed — with no demo data visible
- [ ] BBC News and Guardian articles appear in News tab for users who follow those accounts
- [ ] Follow request flow works end-to-end (request → approve/decline → notification)
- [ ] No JavaScript parse errors that crash the app

### Seed (0 → 500 users)
- [ ] 5,000 East London waitlist signups
- [ ] 500 active users, DAU/MAU ≥ 25%
- [ ] KYC real implementation shipped (Onfido)
- [ ] Zero data selling, verified GDPR compliance

### Series A trigger (500K MAU)
- [ ] £1M ARR (Hatch Plus subscriptions live)
- [ ] Second EU market live (Berlin or Amsterdam)
- [ ] DAU/MAU ≥ 35%
