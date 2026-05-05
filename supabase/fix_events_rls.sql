-- Fix infinite RLS recursion on events table
-- The followers/invitees read policies referenced other tables that also
-- had RLS policies referencing back to events, causing mutual recursion.
-- Simplified versions only check auth.uid() = user_id (owner-only access).

-- Drop the two policies that caused the recursion
DROP POLICY IF EXISTS "events: followers read" ON public.events;
DROP POLICY IF EXISTS "events: invitees read"  ON public.events;

-- Recreate without cross-table references
CREATE POLICY "events: followers read"
  ON public.events FOR SELECT
  USING (visibility = 'private' AND auth.uid() = user_id);

CREATE POLICY "events: invitees read"
  ON public.events FOR SELECT
  USING (visibility = 'invite' AND auth.uid() = user_id);
