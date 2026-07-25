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

// ── TOTP (time-based one-time password) ───────────────────────────────────────
function totp(base32Secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean    = base32Secret.replace(/\s/g, '').toUpperCase();
  let bits = 0, val = 0;
  const bytes = [];
  for (const ch of clean) {
    const v = alphabet.indexOf(ch);
    if (v < 0) continue;
    val = (val << 5) | v;
    bits += 5;
    if (bits >= 8) { bytes.push((val >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  const key    = Buffer.from(bytes);
  const T      = Math.floor(Date.now() / 1000 / 30);
  const msg    = Buffer.allocUnsafe(8);
  msg.writeBigUInt64BE(BigInt(T));
  const hmac   = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = hmac[19] & 0xf;
  const code   = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return code.toString().padStart(6, '0');
}

// ── HTTP client factory ────────────────────────────────────────────────────────
function makeClient() {
  return wrapper(axios.create({
    jar: new CookieJar(),
    withCredentials: true,
    maxRedirects: 10,
    timeout: 30_000,
    headers: {
      'User-Agent'     : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
      'Accept'         : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
    },
  }));
}

// ── Login ──────────────────────────────────────────────────────────────────────
async function login(client) {
  // Fetch login page → grab CSRF token
  const lp    = await client.get(LOGIN_URL);
  const $lp   = cheerio.load(lp.data);
  const csrf  = $lp('input[name="_token"]').val()
             || $lp('meta[name="csrf-token"]').attr('content')
             || '';

  // POST credentials
  const body = new URLSearchParams({
    email   : process.env.APEX_EMAIL    || '',
    password: process.env.APEX_PASSWORD || '',
    _token  : csrf,
  });
  const res = await client.post(LOGIN_URL, body.toString(), {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Referer'     : LOGIN_URL,
    },
  });

  // Handle 2FA if prompted
  const finalUrl = res.request?.res?.responseUrl || '';
  const isHtml   = typeof res.data === 'string';
  if (finalUrl.includes('two-factor') || (isHtml && res.data.includes('two-factor-challenge'))) {
    if (!process.env.APEX_TOTP_SECRET) {
      throw new Error('2FA_REQUIRED — set APEX_TOTP_SECRET environment variable');
    }
    const $tf  = cheerio.load(res.data);
    const csrf2 = $tf('input[name="_token"]').val() || '';
    await client.post('https://apextraderfunding.com/two-factor-challenge',
      new URLSearchParams({ code: totp(process.env.APEX_TOTP_SECRET), _token: csrf2 }).toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  }
}

// ── Parse trading-details page ─────────────────────────────────────────────────
function parseTradingPage(html) {
  const $ = cheerio.load(html);
  const sessions    = [];
  const adjustments = [];

  $('table').each((_, tbl) => {
    const headers = $(tbl).find('th').map((__, th) =>
      $(th).text().toLowerCase().trim()).get().join(' ');

    if (headers.includes('trade date') || headers.includes('closed')) {
      $(tbl).find('tr').slice(1).each((__, row) => {
        const td = $(row).find('td');
        if (td.length < 3) return;
        const date  = $(td[0]).text().trim();
        const pnl   = parseFloat($(td[2]).text().replace(/[$,\s]/g, ''));
        const fills = parseInt($(td[3]).text().trim()) || 0;
        if (date && !isNaN(pnl)) sessions.push({ date, pnl, fills });
      });
    }

    if (headers.includes('adjustment') || (headers.includes('amount') && headers.includes('comment'))) {
      $(tbl).find('tr').slice(1).each((__, row) => {
        const td = $(row).find('td');
        if (td.length < 3) return;
        const date    = $(td[0]).text().trim();
        const amount  = $(td[1]).text().trim();
        const comment = $(td[2]).text().trim();
        if (date && amount) adjustments.push({ date, amount, comment });
      });
    }
  });

  return { sessions, adjustments };
}

// ── Parse summary page ─────────────────────────────────────────────────────────
function parseSummaryPage(html) {
  const text = cheerio.load(html).text();
  const grab = rx => { const m = text.match(rx); return m ? m[1].trim() : null; };
  return {
    balance    : grab(/Current Balance:\s*([\$\d,\.]+)/i),
    totalProfit: grab(/Total Profit:\s*([\$\d,\.]+)/i),
    status     : text.includes('Ineligible') ? 'Ineligible'
               : text.includes('Eligible')   ? 'Eligible' : 'Unknown',
  };
}

// ── Date normalizer ────────────────────────────────────────────────────────────
function normDate(raw) {
  if (!raw) return null;
  raw = raw.trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) return raw;                     // YYYY-MM-DD
  const m1 = raw.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (m1) return `${m1[3]}-${m1[1].padStart(2,'0')}-${m1[2].padStart(2,'0')}`;
  const m2 = raw.match(/^(\d{1,2})-(\d{1,2})-(\d{4})$/);
  if (m2) return `${m2[3]}-${m2[1].padStart(2,'0')}-${m2[2].padStart(2,'0')}`;
  return null;
}

// ── Main fetch ─────────────────────────────────────────────────────────────────
async function fetchApexData() {
  const client = makeClient();
  await login(client);

  const [tradingRes, summaryRes] = await Promise.all([
    client.get(`${BASE}/member/account/trading?account=${ACCOUNT_ID}`),
    client.get(`${BASE}/member/account/summary?account=${ACCOUNT_ID}`),
  ]);

  const { sessions, adjustments } = parseTradingPage(tradingRes.data);
  const { balance, totalProfit, status } = parseSummaryPage(summaryRes.data);

  // Build adjustment map keyed to the VIOLATION date (from comment)
  const adjMap = {};
  for (const a of adjustments) {
    const raw = a.comment.match(/(\d{1,2}[-\/]\d{1,2}[-\/]\d{4})/);
    const key = raw ? normDate(raw[1]) : normDate(a.date);
    if (key) adjMap[key] = (adjMap[key] || 0) + parseFloat(a.amount.replace(/[$,]/g, ''));
  }

  // Build daily entries (net = gross + adjustment)
  const entries = sessions
    .map(s => {
      const date = normDate(s.date);
      if (!date) return null;
      const adj    = adjMap[date] || 0;
      const netPnl = Math.round((s.pnl + adj) * 100) / 100;
      const note   = adj
        ? `Gross $${s.pnl.toFixed(2)}, adj ${adj < 0 ? '-' : '+'}$${Math.abs(adj).toFixed(2)}`
        : `${s.fills} fills`;
      return { date, pnl: netPnl, grossPnl: s.pnl, adjustment: adj, fills: s.fills, notes: note };
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

// ── Cache ──────────────────────────────────────────────────────────────────────
let cache = null, cacheTs = 0;
const CACHE_TTL = 5 * 60 * 1000;   // 5 min

app.get('/api/data', async (req, res) => {
  const fresh = req.query.force === '1';
  if (!fresh && cache && Date.now() - cacheTs < CACHE_TTL) {
    return res.json({ ...cache, cached: true });
  }
  try {
    const data = await fetchApexData();
    cache = data; cacheTs = Date.now();
    res.json(data);
  } catch (err) {
    console.error('Apex fetch error:', err.message);
    if (cache) return res.json({ ...cache, cached: true, fetchError: err.message });
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/health', (_, res) => res.json({ ok: true, cached: !!cache }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Apex Tracker running on :${PORT}`));
