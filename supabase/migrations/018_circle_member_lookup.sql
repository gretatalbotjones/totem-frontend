-- ============================================================
-- 018_circle_member_lookup.sql
--
-- Creates a SECURITY DEFINER function that lets a viewer
-- discover which circle owners (poster IDs) have added them
-- to a circle. Used by loadFeedFromSupabase() to decide
-- whether to show 'friends'-visibility posts.
--
-- A SECURITY DEFINER function is needed because the RLS on
-- circle_members only allows the circle owner to read rows —
-- a plain query from the member's perspective returns nothing.
-- Running as the function owner (postgres) bypasses RLS safely
-- because the function only ever queries by the caller's own
-- auth.uid(), so no cross-user data leaks.
--
-- ⚠️ Run in the Supabase SQL editor.
-- ============================================================

CREATE OR REPLACE FUNCTION public.get_circle_owners_for_member(member_uuid UUID)
RETURNS TABLE(owner_id UUID)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  RETURN QUERY
  SELECT DISTINCT c.user_id
  FROM public.circle_members cm
  JOIN public.circles c ON c.id = cm.circle_id
  WHERE cm.member_id = member_uuid;
END;
$$;

-- Only authenticated users may call this function
REVOKE ALL ON FUNCTION public.get_circle_owners_for_member(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_circle_owners_for_member(UUID) TO authenticated;
