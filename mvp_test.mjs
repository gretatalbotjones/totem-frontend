import { createClient } from '@supabase/supabase-js';

const URL  = 'https://ocztxpmmbopcbtshetts.supabase.co';
const KEY  = 'sb_publishable_QcqD9p8Wk8zHRV-dsSQ4Xw_bVkdC2fy';
const sb   = createClient(URL, KEY);

const pass = (msg) => console.log('  PASS —', msg);
const fail = (msg) => console.error('  FAIL —', msg);
const skip = (msg) => console.warn('  SKIP —', msg);

// ── Resolve a real user session ──────────────────────────────
const { data: { session } } = await sb.auth.getSession();
const userId = session?.user?.id ?? null;

console.log('\n[Totem MVP Tests]');
console.log('Session:', userId ? `${session.user.email} (${userId.slice(0,8)}…)` : 'none — tests requiring auth will skip\n');

// ── Feature 1: Profile editing ────────────────────────────────
console.log('Feature 1: Profile editing');
if (!userId) { skip('no session'); }
else {
  const testBio = 'mvp-test-' + Date.now();
  const { error: updErr } = await sb.from('profiles').update({ bio: testBio }).eq('id', userId);
  if (updErr) { fail('profile update: ' + updErr.message); }
  else {
    const { data } = await sb.from('profiles').select('bio').eq('id', userId).single();
    data?.bio === testBio ? pass('bio saved and read back correctly') : fail('bio mismatch: ' + data?.bio);
    // restore
    await sb.from('profiles').update({ bio: null }).eq('id', userId);
  }
}

// ── Feature 2: Diary entries ──────────────────────────────────
console.log('Feature 2: Diary entries');
if (!userId) { skip('no session'); }
else {
  const { data: row, error } = await sb
    .from('posts')
    .insert({ user_id: userId, caption: 'test diary entry', feed_type: 'diary', visibility: 'friends', created_at: new Date().toISOString() })
    .select().single();
  if (error) { fail('diary insert: ' + error.message); }
  else {
    row?.feed_type === 'diary'
      ? pass('row saved with feed_type=diary, id=' + row.id.slice(0,8))
      : fail('feed_type mismatch: ' + row?.feed_type);
    await sb.from('posts').delete().eq('id', row.id);
  }
}

// ── Feature 3: Event creation ─────────────────────────────────
console.log('Feature 3: Events');
if (!userId) { skip('no session'); }
else {
  const { data: ev, error: evErr } = await sb
    .from('events')
    .insert({ user_id: userId, title: 'Test Event', visibility: 'public', created_at: new Date().toISOString() })
    .select().single();
  if (evErr) { fail('event insert: ' + evErr.message); }
  else {
    ev?.title === 'Test Event'
      ? pass('event saved to events table, id=' + ev.id.slice(0,8))
      : fail('title mismatch: ' + ev?.title);
    await sb.from('events').delete().eq('id', ev.id);
  }
}

// ── Feature 4: Feed from Supabase ────────────────────────────
console.log('Feature 4: Feed');
if (!userId) { skip('no session'); }
else {
  const { data, error } = await sb
    .from('posts')
    .select('id, content, user_id, profiles(name, full_name)')
    .neq('feed_type', 'diary')
    .order('created_at', { ascending: false })
    .limit(5);
  if (error) { fail('feed query: ' + error.message); }
  else {
    pass(`feed query returned ${data?.length ?? 0} post(s) (RLS applied)`);
  }
}

console.log('');
