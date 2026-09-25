# Design Principles

## What good looks like

A Hatch screen feels like a well-designed print magazine opened on a phone. Warm, considered, unhurried. It does not feel like a social media app trying to extract attention. A user should feel *calm* after opening Hatch, not stimulated.

Good: clean white space, warm off-white backgrounds, navy as the only strong colour, editorial typography, no badges demanding attention except when genuinely needed.

Bad: red notification counts on everything, infinite scroll with no end, auto-playing video, sponsored content disguised as organic, motion that exists to impress rather than orient.

---

## Design references

- **Monocle magazine** — editorial warmth, unhurried, premium without being cold
- **Spotify** — utility that became loved; functional without being clinical
- **Notion** — calm, productive, respects the user's focus
- **Phantom wallet** — mobile-first, clean, dark/light works equally well
- **The Guardian** — digital editorial that respects text

**What we are not:** Instagram (dopamine-maximised), Twitter/X (anxiety-inducing), TikTok (compulsive), LinkedIn (performative).

---

## Emotional goals

When a user opens Hatch they should feel:
- **Safe** — this is a private space, not a public stage
- **Present** — the content is from people I actually know
- **Calm** — nothing is trying to hijack my attention
- **In control** — I chose who sees this, and I can change it

When a user shares something they should feel:
- **Comfortable** — the audience is exactly who I intended
- **Heard** — the people who matter will see this
- **Not judged** — there is no public like count, no viral pressure

---

## Anti-patterns

Never build these into Hatch, regardless of how they'd affect metrics:

| Anti-pattern | Why it's banned |
|---|---|
| Infinite algorithmic scroll | Designed to maximise time-on-app, not user value |
| Read receipts without consent | Creates social anxiety, erodes safety |
| Public like/follower counts on feed | Turns sharing into performance |
| Auto-play video | Hijacks attention without consent |
| Red notification badges for non-urgent items | Creates compulsive checking |
| "X people viewed your profile" | Surveillance culture |
| Algorithmic content without user control | Black box manipulation |
| Moving features from free to paid | Explicitly forbidden — builds resentment, kills trust |
| Dark patterns in privacy settings | Contradicts the product promise |

---

## Visual rules

### Colour
```
--bg:           #f7f5f2   Page background — warm off-white, paper-like
--surface:      #ffffff   Cards, modals
--surface2:     #f0ede8   Inputs, secondary surfaces
--border:       #e2ddd8   Standard borders
--text:         #1a1714   Near-black, warm
--muted:        #8a837c   Labels, secondary text
--accent:       #191D64   Navy — primary brand colour, buttons, links
--accent-light: #e8eaf6   Hover tints
--red:          #c0392b   Destructive only
--green:        #27ae60   Success/confirmation only
--gold:         #c9a227   Verification pending, premium signals
```

### Typography
- **Wordmark:** Abadi MT Condensed / Century Gothic / Gill Sans — all-caps or small-caps `hatch`
- **Body/UI:** Outfit (Google Fonts) — 300, 400, 500, 600
- **Italic accent:** Cormorant Garamond — 400 or 600 italic, used sparingly for warmth

### Spacing and shape
- `border-radius: 14px` on all cards, modals, buttons
- `max-width: 600px` — mobile-first, centred on desktop
- `16px` horizontal padding on content
- `box-shadow: 0 2px 12px rgba(26,23,20,0.08)` — subtle lift only
- Touch targets: minimum 44px height

### Images in the feed
- Post images are **full screen width** — no horizontal padding, no rounded corners, no card border around them
- The image bleeds edge to edge; the caption and actions sit below it with normal padding
- This is the same pattern as Instagram Stories and native camera roll — images feel immersive, not boxed in
- Carousels follow the same rule — full width, swipe horizontally, dots indicator below
- Thumbnails in grids (profile page, collections) may have radius; feed images never do

### Minimalism
- Every element on screen must earn its place. If removing it would not confuse the user, remove it.
- No decorative dividers, drop shadows for depth, or visual flourishes that don't carry information
- White space is not wasted space — it is how the content breathes
- Prefer one strong typographic hierarchy over multiple colours, weights, and sizes competing for attention
- When in doubt, do less

### Motion
- Tab transitions: `fadeUp 0.28s ease`
- Modal open: slide up from bottom
- Skeleton: shimmer animation only — no bouncing, no spring physics
- Never animate for decoration. Animate to orient.

---

## UX principles

**1. Privacy defaults are conservative.** Every post defaults to the most private reasonable audience. Users consciously widen, never accidentally expose.

**2. Chronological unless chosen otherwise.** The default feed is reverse-chronological. Algorithmic blending is labelled and opt-in via the Explore mode.

**3. Audience is always visible before posting.** The audience chip (Everyone / Circles / Event) is always visible in the composer. There is no hidden default.

**4. Optimistic UI with honest rollback.** Likes, saves, follows update immediately and roll back visibly with an error toast if the write fails. Never leave the user uncertain about whether something happened.

**5. One toast at a time.** Toast messages are non-blocking, auto-dismiss in 2.8s, appear bottom-centre. Never stack more than one. Never use them for errors that need a decision.

**6. Modals slide up, not over.** All modals use the bottom-sheet pattern. Tap outside to close. Always a visible × button. Never trap the user.

**7. Empty states are instructive.** An empty feed says "Follow people to see their posts here ✦" — it tells the user what to do, not just that nothing exists.

**8. Verified = trustworthy, not superior.** The verified badge indicates KYC completion, not status. Outlet accounts (BBC, Guardian) show it. So should every real user once KYC is implemented.

**9. No metric anxiety.** Follower counts are visible on profiles but not on individual posts in the feed. Likes are shown but not prominently. We do not display "trending" content.

**10. Actions are never ambiguous.** Every button has a clear label or a clearly understood icon. No mystery meat navigation. If you can't tell what a button does without tapping it, redesign it.
