-- ============================================================
-- 008_follow_requests.sql
--
-- Follow request flow for private accounts.
-- Public accounts are followed instantly (no row needed).
-- ============================================================

CREATE TABLE public.follow_requests (
  id           UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  requester_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
  target_id    UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
  status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'approved', 'declined')),
  created_at   TIMESTAMPTZ DEFAULT now(),
  UNIQUE(requester_id, target_id)
);

ALTER TABLE public.follow_requests ENABLE ROW LEVEL SECURITY;

-- Requester can insert and delete their own requests
CREATE POLICY "requester can manage own requests"
  ON public.follow_requests
  FOR ALL USING (requester_id = auth.uid());

-- Target can read and update requests directed at them
CREATE POLICY "target can read and update incoming requests"
  ON public.follow_requests
  FOR ALL USING (target_id = auth.uid());
