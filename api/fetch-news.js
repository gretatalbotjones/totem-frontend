// api/fetch-news.js
//
// Vercel serverless function — fetches BBC and Guardian RSS feeds,
// parses each item's headline, snippet, image and link, and inserts
// new articles into the Supabase posts table as outlet account posts.
//
// Called on a schedule by vercel.json (every hour).
// Secured by CRON_SECRET environment variable.
//
// Required environment variables (set in Vercel project settings):
//   SUPABASE_URL         — e.g. https://ocztxpmmbopcbtshetts.supabase.co
//   SUPABASE_SERVICE_KEY — service_role key from Supabase Settings → API
//   CRON_SECRET          — any random string; set the same value in Vercel

const BBC_NEWS_ID = 'a0000000-0000-0000-0000-000000000001';
const GUARDIAN_ID = 'a0000000-0000-0000-0000-000000000002';

const FEEDS = [
  {
    url:       'https://feeds.bbci.co.uk/news/rss.xml',
    profileId: BBC_NEWS_ID,
    source:    'BBC News',
  },
  {
    url:       'https://www.theguardian.com/uk/rss',
    profileId: GUARDIAN_ID,
    source:    'The Guardian',
  },
  {
    url:       'https://www.theguardian.com/world/rss',
    profileId: GUARDIAN_ID,
    source:    'The Guardian',
  },
  {
    url:       'https://www.theguardian.com/technology/rss',
    profileId: GUARDIAN_ID,
    source:    'The Guardian',
  },
  {
    url:       'https://www.theguardian.com/environment/rss',
    profileId: GUARDIAN_ID,
    source:    'The Guardian',
  },
];

// ── XML parsing (no npm dependency) ──────────────────────────────────────────

function extractText(block, tag) {
  const re = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i');
  const m = block.match(re);
  if (!m) return null;
  return m[1]
    .replace(/<!\[CDATA\[/g, '')
    .replace(/\]\]>/g, '')
    .replace(/<[^>]+>/g, '')   // strip any inline HTML
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .trim();
}

function extractAttr(block, tag, attr) {
  const re = new RegExp(`<${tag}[^>]*\\s${attr}="([^"]*)"`, 'i');
  const m = block.match(re);
  return m ? m[1] : null;
}

// Extract the raw text of a <link> element — RSS often uses a bare text node
// between tags (not an attribute) for the article URL.
function extractLink(block) {
  // Try plain <link>...</link> first
  const m = block.match(/<link>([\s\S]*?)<\/link>/i);
  if (m) return m[1].replace(/<!\[CDATA\[|\]\]>/g, '').trim();
  // Fallback: atom:link href attribute
  return extractAttr(block, 'atom:link', 'href');
}

function parseItems(xml) {
  const items = [];
  const re = /<item>([\s\S]*?)<\/item>/gi;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const block = m[1];
    const title       = extractText(block, 'title');
    const link        = extractLink(block);
    const description = extractText(block, 'description');
    const pubDate     = extractText(block, 'pubDate');
    // BBC uses <media:thumbnail url="..."/>, Guardian uses <media:content url="..."/>
    const imageUrl    = extractAttr(block, 'media:thumbnail', 'url')
                     || extractAttr(block, 'media:content',   'url')
                     || null;
    if (title && link) {
      items.push({ title, link, description, pubDate, imageUrl });
    }
  }
  return items;
}

// Trim to a couple of sentences, max 280 chars
function truncateSnippet(text, max = 280) {
  if (!text || text.length <= max) return text || '';
  const cut = text.slice(0, max);
  const last = Math.max(cut.lastIndexOf('. '), cut.lastIndexOf('! '), cut.lastIndexOf('? '));
  return last > 80 ? cut.slice(0, last + 1) : cut.trimEnd() + '…';
}

// ── Supabase REST helpers (no SDK dependency) ─────────────────────────────────

function supabaseHeaders(serviceKey) {
  return {
    'apikey':        serviceKey,
    'Authorization': `Bearer ${serviceKey}`,
    'Content-Type':  'application/json',
  };
}

async function postExists(supabaseUrl, serviceKey, externalUrl) {
  const url = `${supabaseUrl}/rest/v1/posts?external_url=eq.${encodeURIComponent(externalUrl)}&select=id&limit=1`;
  const res = await fetch(url, { headers: supabaseHeaders(serviceKey) });
  if (!res.ok) return false;
  const data = await res.json();
  return Array.isArray(data) && data.length > 0;
}

async function insertPost(supabaseUrl, serviceKey, row) {
  const res = await fetch(`${supabaseUrl}/rest/v1/posts`, {
    method:  'POST',
    headers: { ...supabaseHeaders(serviceKey), 'Prefer': 'return=minimal' },
    body:    JSON.stringify(row),
  });
  return res;
}

// ── Handler ───────────────────────────────────────────────────────────────────

module.exports = async function handler(req, res) {
  // Verify the Vercel cron secret so random callers can't trigger ingestion
  const cronSecret = process.env.CRON_SECRET;
  if (cronSecret) {
    const auth = req.headers['authorization'];
    if (auth !== `Bearer ${cronSecret}`) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceKey  = process.env.SUPABASE_SERVICE_KEY;

  if (!supabaseUrl || !serviceKey) {
    return res.status(500).json({ error: 'SUPABASE_URL or SUPABASE_SERVICE_KEY not set' });
  }

  let inserted = 0;
  const errors = [];

  for (const feed of FEEDS) {
    try {
      const feedRes = await fetch(feed.url, {
        headers: { 'User-Agent': 'HatchApp/1.0 (news-aggregator)' },
        signal:  AbortSignal.timeout(10000),
      });
      if (!feedRes.ok) throw new Error(`HTTP ${feedRes.status} from ${feed.url}`);

      const xml   = await feedRes.text();
      const items = parseItems(xml);

      for (const item of items.slice(0, 10)) {
        try {
          if (await postExists(supabaseUrl, serviceKey, item.link)) continue;

          const snippet = truncateSnippet(item.description || '');
          // caption = headline + blank line + snippet (so index.html can split on \n\n)
          const caption = snippet
            ? `${item.title}\n\n${snippet}`
            : item.title;

          const insertRes = await insertPost(supabaseUrl, serviceKey, {
            user_id:      feed.profileId,
            caption,
            image_url:    item.imageUrl || null,
            external_url: item.link,
            feed_type:    'news',
            visibility:   'public',
          });

          if (insertRes.status === 201 || insertRes.status === 200) {
            inserted++;
          } else {
            const body = await insertRes.text();
            errors.push(`Insert failed (${insertRes.status}) for ${item.link}: ${body.slice(0, 200)}`);
          }
        } catch (itemErr) {
          errors.push(`Item error (${item.link}): ${itemErr.message}`);
        }
      }
    } catch (feedErr) {
      errors.push(`Feed error (${feed.url}): ${feedErr.message}`);
    }
  }

  return res.status(200).json({ inserted, errors, feeds: FEEDS.length });
}
