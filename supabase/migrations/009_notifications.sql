-- ============================================================
-- 009_notifications.sql
--
-- Persisted notifications table. Used for follow requests,
-- follow approvals, and event invites.
-- ============================================================

CREATE TABLE public.notifications (
  id           UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id      UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
  type         TEXT NOT NULL,
  actor_id     UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
  reference_id UUID,
  text         TEXT,
  read         BOOLEAN DEFAULT false,
  created_at   TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users can read own notifications"
  ON public.notifications
  FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "users can update own notifications"
  ON public.notifications
  FOR UPDATE USING (user_id = auth.uid());

CREATE POLICY "authenticated users can insert notifications"
  ON public.notifications
  FOR INSERT WITH CHECK (auth.uid() IS NOT NULL);
