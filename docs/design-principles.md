# Hatch — Design Principles

## Brand identity

**Feeling:** Premium, private, considered. Not loud. Not addictive.
**Contrast to competitors:** Instagram feels performative. Twitter/X feels hostile. Hatch feels like a private members' club.

**Name:** "hatch" — lowercase in wordmark. Suggests emergence, intimacy, a protected space.

---

## Visual design

### Colour palette

| Token | Value | Usage |
|---|---|---|
| `--bg` | `#f7f5f2` | Page background — warm off-white, paper-like |
| `--surface` | `#ffffff` | Cards, modals, panels |
| `--surface2` | `#f0ede8` | Inputs, secondary surfaces |
| `--border` | `#e2ddd8` | Default borders |
| `--border2` | `#d0cac3` | Stronger borders |
| `--text` | `#1a1714` | Primary text — near-black, warm |
| `--muted` | `#8a837c` | Secondary text, labels |
| `--accent` | `#191D64` | Navy — primary brand colour, buttons, links |
| `--accent-light` | `#e8eaf6` | Accent tint for hover states |
| `--accent2` | `#2c5282` | Secondary accent (news source tags) |
| `--red` | `#c0392b` | Destructive actions, recording indicator |
| `--green` | `#27ae60` | Success, going/confirmed states |
| `--gold` | `#c9a227` | Verification pending, premium signals |

### Typography

| Role | Family | Weight |
|---|---|---|
| Wordmark / display | Abadi MT Condensed / Century Gothic / Gill Sans | 700 |
| Body / UI | Outfit (Google Fonts) | 300, 400, 500, 600 |
| Italic accent | Cormorant Garamond (Google Fonts) | 400, 600 italic |

The warm, editorial font pairing (Cormorant + Outfit) signals quality and restraint. Avoid system fonts in production.

### Spacing and shape

- `--radius: 14px` — primary border radius (cards, modals, buttons)
- `--shadow: 0 2px 12px rgba(26,23,20,0.08)` — subtle lift
- `--shadow-md: 0 4px 24px rgba(26,23,20,0.12)` — modal elevation
- Max content width: `600px` — mobile-first, centred on desktop
- Consistent `16px` horizontal padding on content

---

## UI patterns

### Layout

- **Top nav:** sticky, blurred background (`backdrop-filter: blur(14px)`), logo centred, search + notifications in corners
- **Bottom tab bar:** 5 tabs (Feed, Events, + Create, Messages, Profile); z-index 355
- **Tab pages:** full-height, fade-up animation on switch (`fadeUp 0.28s ease`)
- **Modals:** slide up from bottom (`.modal-sheet`), overlay with `closeModalByOverlay` tap-outside-to-close

### Interaction

- **Optimistic UI:** likes, saves, follows update instantly and roll back on error
- **Toasts:** non-blocking feedback, bottom-centre, auto-dismiss 2.8s
- **Skeleton loading:** shimmer placeholders while feed loads
- **Pull-to-refresh equivalent:** feed reloads when switching back to feed tab

### Feed post card

Structure (top to bottom):
1. Image (carousel if multi-image, tappable for news)
2. Footer: avatar + author name (tappable for non-own posts) + caption
3. Actions: like / comment / share / save + timestamp
4. Audience label (if circles/event audience)
5. Tagged people
6. Comments section (collapsible)

### Profile

- Large avatar (76px, circle, upload-on-tap)
- Stats row: posts / followers / following (all tappable)
- Bio text
- Sub-nav tabs: Photos / Pulse / Tagged / Saved
- Diary strip (own profile only)
- Collections strip

### Diary ring

- Circular avatar ring in the feed header strip
- Unseen = coloured ring, Seen = grey ring
- Own ring has a + add button
- Tapping opens fullscreen viewer

---

## Design principles (functional)

1. **Privacy by default.** Every post defaults to a conservative audience. Users consciously choose to share wider.
2. **Chronological first.** The default feed is reverse-chronological. Algorithmic sorting is opt-in.
3. **No engagement bait.** No likes count shown prominently. No infinite algorithmic scroll designed to maximise time-on-app.
4. **Real people only.** Verified badge signals identity has been confirmed. Outlet accounts (BBC, Guardian) are clearly machine-managed.
5. **Mobile-first.** Design decisions are made for a 390px wide screen. Desktop is a wider version of the same layout.

---

## Component inventory (prototype → Next.js mapping)

| Prototype element | Next.js component |
|---|---|
| `tab-feed` + feed sub-nav | `app/(app)/feed/page.tsx` + `FeedSubNav` |
| Post card | `components/feed/PostCard.tsx` |
| Diary strip | `components/diary/DiaryStrip.tsx` |
| `tab-events` | `app/(app)/events/page.tsx` |
| Calendar (month + week) | `components/events/Calendar.tsx` |
| `tab-notifs` | `app/(app)/notifications/page.tsx` |
| Follow request card | `components/notifications/FollowRequestCard.tsx` |
| `tab-profile` | `app/(app)/profile/page.tsx` |
| Friend profile modal | `app/(app)/profile/[id]/page.tsx` (or drawer) |
| Post modal | `components/post/CreatePostModal.tsx` |
| Pulse modal | `components/post/CreatePulseModal.tsx` |
| Diary modal | `components/diary/CreateDiaryModal.tsx` |
| Event modal | `components/events/CreateEventModal.tsx` |
| Avatar upload modal | `components/profile/AvatarUpload.tsx` |
| Circles manager | `components/circles/CircleManager.tsx` |
| Search overlay | `components/search/SearchOverlay.tsx` |
| Bottom tab bar | `components/ui/BottomNav.tsx` |
| Top nav | `components/ui/TopNav.tsx` |
| Auth screens | `app/(auth)/` pages |
| Toast | `components/ui/Toast.tsx` |
| Skeleton | `components/ui/Skeleton.tsx` |

---

## Accessibility notes

- All interactive elements need `aria-label` (currently missing in prototype)
- Focus management needed for modals (currently not implemented)
- Colour contrast: `--text` on `--bg` passes AA; `--muted` on `--bg` marginal — check in Next.js build
- Touch targets: all buttons should be ≥44px tall (mostly satisfied in current design)
