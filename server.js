const express = require('express');
const axios   = require('axios');
const { wrapper } = require('axios-cookiejar-support');
const { CookieJar } = require('tough-cookie');
const cheerio = require('cheerio');
const crypto  = require('crypto');
const path    = require('path');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));

const ACCOUNT_ID  = process.env.APEX_ACCOUNT_ID || 'PA-APEX-383013-03';
const BASE        = 'https://dashboard.apextraderfunding.com';
const LOGIN_URL   = 'https://dashboard.apextraderfunding.com/login';
const DATA_URL    = `${BASE}/member/account-details/get-trading-details`;

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
    timeout: 25_000,
    headers: {
      'User-Agent'     : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36',
      'Accept'         : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
    },
  }));
}

// ── Helpers ────────────────────────────────────────────────────────────────
function extractFormFields(html) {
  const $ = cheerio.load(html);
  const fields = {};
  $('form').each((_, form) => {
    $(form).find('input, select, textarea').each((_, el) => {
      const name  = $(el).attr('name');
      const type  = $(el).attr('type') || $(el).prop('tagName').toLowerCase();
      const value = $(el).val() || '';
      if (name) fields[name] = { type, value: type === 'password' ? '***' : value.slice(0, 50) };
    });
  });
  return fields;
}

// Normalise M/D/YYYY or YYYY-MM-DD → YYYY-MM-DD
function normDate(raw) {
  if (!raw) return null;
  const s = String(raw).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  const m = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})$/);
  if (m) return `${m[3]}-${m[1].padStart(2,'0')}-${m[2].padStart(2,'0')}`;
  return null;
}

// ── Login (aMember Pro + TOTP 2FA) ─────────────────────────────────────────
async function login(client) {
  const lp  = await client.get(LOGIN_URL);
  const $lp = cheerio.load(lp.data);
  const loginAttemptId = $lp('input[name="login_attempt_id"]').val() || '';

  const res = await client.post(
    LOGIN_URL,
    new URLSearchParams({
      amember_login    : process.env.APEX_EMAIL    || '',
      amember_pass     : process.env.APEX_PASSWORD || '',
      login_attempt_id : loginAttemptId,
      login            : 'Log In',
    }).toString(),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Referer': LOGIN_URL } }
  );

  const finalUrl = res.request?.res?.responseUrl || res.config?.url || '';
  const html2fa  = typeof res.data === 'string' ? res.data : '';
  const is2FA = /two.?factor|totp|2fa|amember_totp|confirm.{0,30}identity|one.time.password/i.test(finalUrl + html2fa);

  if (is2FA) {
    if (!process.env.APEX_TOTP_SECRET) throw new Error('2FA_REQUIRED');
    const $tf     = cheerio.load(html2fa);
    const tfAction = $tf('form').attr('action') || '';
    const tfUrl   = tfAction.startsWith('http') ? tfAction : `${BASE}${tfAction || '/login'}`;
    const hiddenFields = {};
    $tf('input[type="hidden"]').each((_, el) => {
      const n = $tf(el).attr('name'), v = $tf(el).val() || '';
      if (n) hiddenFields[n] = v;
    });
    const tfField = $tf('input[type="text"], input[type="number"]')
      .filter((_, el) => !['amember_login','login'].includes($tf(el).attr('name') || ''))
      .first().attr('name') || 'pass';
    await client.post(
      tfUrl,
      new URLSearchParams({ ...hiddenFields, [tfField]: totp(process.env.APEX_TOTP_SECRET) }).toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Referer': finalUrl } }
    );
  }
}

// ── Core fetch ─────────────────────────────────────────────────────────────
async function fetchApexData() {
  const client = makeClient();
  await login(client);

  // Hit the JSON API endpoint directly — no HTML scraping
  const r = await client.get(DATA_URL, {
    params: { account_number: ACCOUNT_ID },
    headers: {
      'Accept'  : 'application/json, text/javascript, */*; q=0.01',
      'X-Requested-With': 'XMLHttpRequest',
      'Referer' : `${BASE}/member/account/trading?account=${ACCOUNT_ID}`,
    },
  });

  const json = r.data;
  if (!json || json.success === false) {
    throw new Error(`API returned success:false — status ${r.status}`);
  }

  const chartData    = json.chart_data       || [];
  const adjData      = json.cash_adjustments || [];

  // Sort sessions oldest → newest
  const sessions = [...chartData].sort((a, b) =>
    String(a.TradeDate).localeCompare(String(b.TradeDate))
  );

  // Build adjustment map: key = affected trading date from comment, value = total adj $
  const adjMap = {};
  for (const a of adjData) {
    const commentDate = String(a.comment || '').match(/(\d{1,2}[-\/]\d{1,2}[-\/]\d{4})/);
    const affectedDate = commentDate ? normDate(commentDate[1]) : normDate(a.TradeDate);
    if (affectedDate) {
      adjMap[affectedDate] = Math.round(((adjMap[affectedDate] || 0) + (a.amount || 0)) * 100) / 100;
    }
  }

  // Build entries with net P&L (gross + adjustments)
  const entries = sessions.map(s => {
    const date    = normDate(s.TradeDate);
    if (!date) return null;
    const grossPnl = Math.round((s.ClosedPnl || 0) * 100) / 100;
    const adj      = adjMap[date] || 0;
    const net      = Math.round((grossPnl + adj) * 100) / 100;
    return {
      date,
      pnl       : net,
      grossPnl,
      adjustment: adj,
      fills     : s.Fills || 0,
      notes     : adj !== 0
        ? `Gross $${grossPnl.toFixed(2)}, adj ${adj < 0 ? '-' : '+'}$${Math.abs(adj).toFixed(2)}`
        : `${s.Fills || 0} fills`,
    };
  }).filter(Boolean);

  // Account balance from most recent session
  const mostRecent = chartData.reduce((best, s) =>
    !best || String(s.TradeDate) > String(best.TradeDate) ? s : best, null);
  const balanceNum = mostRecent?.AcctBal;
  const balance = balanceNum != null
    ? '$' + Number(balanceNum).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })
    : null;

  // Total gross profit
  const totalGross  = chartData.reduce((sum, s) => sum + (s.ClosedPnl || 0), 0);
  const totalProfit = `$${(Math.round(totalGross * 100) / 100).toFixed(2)}`;

  return {
    accountId  : ACCOUNT_ID,
    balance,
    totalProfit,
    status     : 'Active',
    entries,
    adjustments: adjData.map(a => ({
      date   : normDate(a.TradeDate),
      amount : a.amount,
      comment: a.comment,
    })),
    lastSync: new Date().toISOString(),
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

// Debug: shows raw JSON API response
app.get('/api/debug', async (req, res) => {
  try {
    const client = makeClient();
    await login(client);
    const r = await client.get(DATA_URL, {
      params: { account_number: ACCOUNT_ID },
      headers: {
        'Accept'           : 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With' : 'XMLHttpRequest',
        'Referer'          : `${BASE}/member/account/trading?account=${ACCOUNT_ID}`,
      },
    });
    res.json({
      status        : r.status,
      success       : r.data?.success,
      sessionCount  : r.data?.chart_data?.length ?? 0,
      adjCount      : r.data?.cash_adjustments?.length ?? 0,
      raw           : r.data,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Step-by-step login debug
app.get('/api/debug-login', async (req, res) => {
  try {
    const client = makeClient();

    const lp = await client.get(LOGIN_URL);
    const formFields = extractFormFields(lp.data);

    const $lp2 = cheerio.load(lp.data);
    const loginAttemptId = $lp2('input[name="login_attempt_id"]').val() || '';
    const loginRes = await client.post(
      LOGIN_URL,
      new URLSearchParams({
        amember_login    : process.env.APEX_EMAIL    || '',
        amember_pass     : process.env.APEX_PASSWORD || '',
        login_attempt_id : loginAttemptId,
        login            : 'Log In',
      }).toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Referer': LOGIN_URL } }
    );
    const loginFinalUrl = loginRes.request?.res?.responseUrl || loginRes.config?.url || '';
    const loginHtml = typeof loginRes.data === 'string' ? loginRes.data : '';
    const has2FA = /two.?factor|totp|2fa|amember_totp|confirm.{0,30}identity|one.time.password/i.test(loginFinalUrl + loginHtml);

    let totpGenerated = null, tfFinalUrl = null;
    if (has2FA) {
      if (!process.env.APEX_TOTP_SECRET) return res.json({ step: '2FA_REQUIRED', loginFinalUrl });
      totpGenerated = totp(process.env.APEX_TOTP_SECRET);
      const $tf    = cheerio.load(loginHtml);
      const tfAction = $tf('form').attr('action') || '';
      const tfUrl  = tfAction.startsWith('http') ? tfAction : `${BASE}${tfAction || '/login'}`;
      const tfField = $tf('input[type="text"], input[type="number"]')
        .filter((_, el) => !['amember_login'].includes($tf(el).attr('name') || ''))
        .first().attr('name') || 'pass';
      const hiddenFields = {};
      $tf('input[type="hidden"]').each((_, el) => {
        const n = $tf(el).attr('name'), v = $tf(el).val() || '';
        if (n) hiddenFields[n] = v;
      });
      const tfRes = await client.post(
        tfUrl,
        new URLSearchParams({ ...hiddenFields, [tfField]: totpGenerated }).toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Referer': loginFinalUrl } }
      );
      tfFinalUrl = tfRes.request?.res?.responseUrl || '';
    }

    // Test the JSON API endpoint
    const apiRes = await client.get(DATA_URL, {
      params: { account_number: ACCOUNT_ID },
      headers: {
        'Accept'           : 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With' : 'XMLHttpRequest',
        'Referer'          : `${BASE}/member/account/trading?account=${ACCOUNT_ID}`,
      },
    });

    res.json({
      envEmail    : process.env.APEX_EMAIL     ? process.env.APEX_EMAIL.slice(0,4)+'...' : 'NOT_SET',
      envPassword : !!process.env.APEX_PASSWORD,
      envTotp     : !!process.env.APEX_TOTP_SECRET,
      formFields,
      loginFinalUrl,
      has2FA,
      totpGenerated,
      tfFinalUrl,
      apiStatus   : apiRes.status,
      apiSuccess  : apiRes.data?.success,
      sessionCount: apiRes.data?.chart_data?.length ?? 0,
      adjCount    : apiRes.data?.cash_adjustments?.length ?? 0,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/health', (_, res) => res.json({ ok: true, cached: !!cache, cacheAge: cache ? Math.round((Date.now()-cacheTs)/1000) : null }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Apex Tracker running on port ${PORT}`));
