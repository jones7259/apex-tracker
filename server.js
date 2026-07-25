const express = require('express');
const axios   = require('axios');
const { wrapper } = require('axios-cookiejar-support');
const { CookieJar } = require('tough-cookie');
const cheerio = require('cheerio');
const crypto  = require('crypto');
const path    = require('path');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));

const ACCOUNT_ID = process.env.APEX_ACCOUNT_ID || 'PA-APEX-383013-03';
const BASE       = 'https://dashboard.apextraderfunding.com';
const LOGIN_URL  = 'https://apextraderfunding.com/member/login';

// ── TOTP (RFC 6238) ────────────────────────────────────────────────────────
function totp(base32Secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = base32Secret.replace(/\s/g, '').toUpperCase();
  let bits = 0, val = 0;
  const bytes = [];
  for (const ch of clean) {
    const v = alphabet.indexOf(ch);
    if (v < 0) continue;
    val = (val << 5) | v;
    bits += 5;
    if (bits >= 8) { bytes.push((val >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  const key  = Buffer.from(bytes);
  const T    = Math.floor(Date.now() / 1000 / 30);
  const msg  = Buffer.allocUnsafe(8);
  msg.writeBigUInt64BE(BigInt(T));
  const hmac = crypto.createHmac('sha1', key).update(msg).digest();
  const off  = hmac[19] & 0xf;
  const code = (hmac.readUInt32BE(off) & 0x7fffffff) % 1_000_000;
  return code.toString().padStart(6, '0');
}

// ── HTTP client with cookie jar ────────────────────────────────────────────
function makeClient() {
  return wrapper(axios.create({
    jar: new CookieJar(),
    withCredentials: true,
    maxRedirects: 10,
    timeout: 30_000,
    headers: {
      'User-Agent'     : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36',
      'Accept'         : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
    },
  }));
}

// ── Login ──────────────────────────────────────────────────────────────────
async function login(client) {
  const lp   = await client.get(LOGIN_URL);
  const $lp  = cheerio.load(lp.data);
  const csrf = $lp('input[name="_token"]').val() ||
               $lp('meta[name="csrf-token"]').attr('content') || '';

  const res = await client.post(
    LOGIN_URL,
    new URLSearchParams({
      email   : process.env.APEX_EMAIL    || '',
      password: process.env.APEX_PASSWORD || '',
      _token  : csrf,
    }).toString(),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Referer': LOGIN_URL } }
  );

  const finalUrl = res.request?.res?.responseUrl || res.config?.url || '';
  const html2fa  = typeof res.data === 'string' ? res.data : '';
  if (finalUrl.includes('two-factor') || html2fa.includes('two-factor-challenge')) {
    if (!process.env.APEX_TOTP_SECRET) throw new Error('2FA_REQUIRED');
    const $tf  = cheerio.load(html2fa);
    const csrf2 = $tf('input[name="_token"]').val() || '';
    await client.post(
      'https://apextraderfunding.com/two-factor-challenge',
      new URLSearchParams({ code: totp(process.env.APEX_TOTP_SECRET), _token: csrf2 }).toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
  }
}

// ── Text-based parsers (robust against table structure changes) ────────────

function parseTradingText(text) {
  const sessions     = [];
  const adjustments  = [];

  // Session rows look like: 2026-07-24  $254,010.00  $1,490.00  10
  // We capture: date, balance, closedPnl, fills
  const sRx = /(\d{4}-\d{2}-\d{2})\s+\$[\d,]+\.?\d*\s+\$([\d,]+\.?\d*)\s+(\d+)/g;
  let m;
  while ((m = sRx.exec(text)) !== null) {
    sessions.push({
      date : m[1],
      pnl  : parseFloat(m[2].replace(/,/g, '')),
      fills: parseInt(m[3], 10),
    });
  }

  // Adjustment rows look like: 2026-07-24  -$50.50  Scaling violation on 7-23-2026
  const aRx = /(\d{4}-\d{2}-\d{2})\s+(-\$[\d,]+\.?\d*)\s+([^\n\r]{5,80})/g;
  while ((m = aRx.exec(text)) !== null) {
    const comment = m[3].trim();
    // Only capture rows that look like adjustments (not session rows re-matched)
    if (/scaling|violation|adjustment|cash/i.test(comment)) {
      adjustments.push({ date: m[1], amount: m[2], comment });
    }
  }

  return { sessions, adjustments };
}

function parseSummaryText(text) {
  // Matches: "Current Balance: $254,010.00"  or  "Current Balance $254,010.00"
  const balM  = text.match(/Current\s+Balance[:\s]+\$([\d,]+\.?\d*)/i);
  const profM = text.match(/Total\s+Profit[:\s]+\$([\d,]+\.?\d*)/i);
  const status = text.includes('Ineligible') ? 'Ineligible'
               : /\bEligible\b/.test(text)   ? 'Eligible'
               : 'Unknown';
  return {
    balance    : balM  ? '$' + balM[1]  : null,
    totalProfit: profM ? '$' + profM[1] : null,
    status,
  };
}

// ── Date normaliser ────────────────────────────────────────────────────────
function normDate(raw) {
  if (!raw) return null;
  const s = raw.trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  const m = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})$/);
  if (m) return `${m[3]}-${m[1].padStart(2,'0')}-${m[2].padStart(2,'0')}`;
  return null;
}

// ── Core fetch ─────────────────────────────────────────────────────────────
async function fetchApexData() {
  const client = makeClient();
  await login(client);

  const [tradingRes, summaryRes] = await Promise.all([
    client.get(`${BASE}/member/account/trading?account=${ACCOUNT_ID}`),
    client.get(`${BASE}/member/account/summary?account=${ACCOUNT_ID}`),
  ]);

  const tradingText = cheerio.load(tradingRes.data).text();
  const summaryText = cheerio.load(summaryRes.data).text();

  const { sessions, adjustments } = parseTradingText(tradingText);
  const { balance, totalProfit, status } = parseSummaryText(summaryText);

  // Build adjustment map keyed by the VIOLATED day (from comment) or the entry date
  const adjMap = {};
  for (const a of adjustments) {
    const dateInComment = a.comment.match(/(\d{1,2}[-\/]\d{1,2}[-\/]\d{4})/);
    const key = normDate(dateInComment ? dateInComment[1] : a.date);
    if (key) adjMap[key] = (adjMap[key] || 0) + parseFloat(a.amount.replace(/[\$,]/g, ''));
  }

  const entries = sessions
    .map(s => {
      const date = normDate(s.date);
      if (!date) return null;
      const adj = adjMap[date] || 0;
      const net = Math.round((s.pnl + adj) * 100) / 100;
      return {
        date,
        pnl        : net,
        grossPnl   : s.pnl,
        adjustment : adj,
        fills      : s.fills,
        notes      : adj
          ? `Gross $${s.pnl.toFixed(2)}, adj ${adj < 0 ? '-' : '+'}$${Math.abs(adj).toFixed(2)}`
          : `${s.fills} fills`,
      };
    })
    .filter(Boolean)
    .sort((a, b) => a.date.localeCompare(b.date));

  return {
    accountId  : ACCOUNT_ID,
    balance,
    totalProfit,
    status,
    entries,
    adjustments,
    lastSync   : new Date().toISOString(),
  };
}

// ── Cache ──────────────────────────────────────────────────────────────────
let cache = null, cacheTs = 0;
const CACHE_TTL = 5 * 60 * 1000;

// ── Routes ─────────────────────────────────────────────────────────────────
app.get('/api/data', async (req, res) => {
  if (req.query.force !== '1' && cache && Date.now() - cacheTs < CACHE_TTL)
    return res.json({ ...cache, cached: true });
  try {
    const data = await fetchApexData();
    cache = data; cacheTs = Date.now();
    res.json(data);
  } catch (err) {
    console.error('Fetch error:', err.message);
    if (cache) return res.json({ ...cache, cached: true, fetchError: err.message });
    res.status(500).json({ error: err.message });
  }
});

// Debug endpoint: shows raw page text so we can verify parser selectors
app.get('/api/debug', async (req, res) => {
  try {
    const client = makeClient();
    await login(client);
    const r = await client.get(`${BASE}/member/account/trading?account=${ACCOUNT_ID}`);
    const text = cheerio.load(r.data).text().replace(/\s+/g, ' ');
    res.json({
      textSample: text.slice(0, 4000),
      fullLength : text.length,
      htmlLength : r.data.length,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/health', (_, res) => res.json({ ok: true, cached: !!cache, cacheAge: cache ? Math.round((Date.now()-cacheTs)/1000) : null }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Apex Tracker running on port ${PORT}`));
