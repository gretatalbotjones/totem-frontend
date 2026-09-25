# Hatch — Next.js App

This directory will contain the Next.js 14 rebuild of the Hatch prototype.

**Status:** Scaffold only. Not yet initialised.

See `docs/migration-plan.md` for the phased build plan.
See `docs/handover.md` for current project state and next actions.
See `docs/architecture.md` for the target architecture and folder rationale.

## Directory map

| Directory | Purpose |
|---|---|
| `app/` | Next.js App Router — pages, layouts, API routes |
| `components/` | React components (feed, profile, events, ui primitives…) |
| `lib/supabase/` | Supabase client (browser + server), generated DB types |
| `store/` | Zustand global store — replaces ~40 global JS variables |
| `docs/` | App-specific docs (symlink or copy from root `docs/` as needed) |
| `agents/` | Agent prompts and task definitions for AI-assisted development |
| `generated/` | Auto-generated files — Supabase types, API schemas (do not hand-edit) |

## To initialise

```bash
cd nextjs-app
npx create-next-app@latest . --typescript --tailwind --app --src-dir no --import-alias "@/*"
npm install @supabase/supabase-js @supabase/ssr zustand
npx supabase gen types typescript --project-id ocztxpmmbopcbtshetts > generated/database.types.ts
```

## Supabase project

Same project as the prototype — no schema changes required to start.

- URL: `https://ocztxpmmbopcbtshetts.supabase.co`
- Anon key: `sb_publishable_QcqD9p8Wk8zHRV-dsSQ4Xw_bVkdC2fy`
- Service key: in Vercel env vars as `SUPABASE_SERVICE_KEY`
