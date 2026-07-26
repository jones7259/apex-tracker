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

// ── Scrape account summary page for requirements ───────────────────────────
async function fetchRequirements(client) {
  try {
    const summaryUrl = `${BASE}/member/account/summary?account=${ACCOUNT_ID}`;
    const res = await client.get(summaryUrl);
    if (typeof res.data !== 'string') return {};
    const text = res.data.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');

    const out = {};

    // Min. Payout Balance / Profit Target  →  e.g. "$256,600.00"
    const ptM = text.match(/(?:Min\.?\s*Payout\s*Balance|Profit\s*Target)\s*[:\s]+\$([\d,]+(?:\.\d+)?)/i);
    if (ptM) out.profitTarget = parseFloat(ptM[1].replace(/,/g,''));

    // Initial Balance
    const ibM = text.match(/Initial\s*Balance\s*[:\s]+\$([\d,]+(?:\.\d+)?)/i);
    if (ibM) out.initialBalance = parseFloat(ibM[1].replace(/,/g,''));

    // Minimum Trading Days  →  e.g. "8 days fills"
    const tdM = text.match(/Minimum\s*Trading\s*Days?\s*[:\s]+(\d+)/i);
    if (tdM) out.minTradingDays = parseInt(tdM[1]);

    // Trading Days >= $X Profit: Y days  →  e.g. "5 days with $150+ profit"
    const pdM = text.match(/Trading\s*Days?\s*>=?\s*\$(\d+)\s*(?:Profit\s*)?[:\s]+(\d+)/i);
    if (pdM) {
      out.minProfitThreshold = parseInt(pdM[1]);
      out.minProfitDays      = parseInt(pdM[2]);
    }

    return out;
  } catch (e) {
    console.error('Summary scrape error:', e.message);
    return {};
  }
}

// ── Core fetch ─────────────────────────────────────────────────────────────
async function fetchApexData() {
  const client = makeClient();
  await login(client);

  // Visit the trading page first
  const tradingPageUrl = `${BASE}/member/account/trading?account=${ACCOUNT_ID}`;
  await client.get(tradingPageUrl);

  // Fetch trading details JSON
  const r = await client.get(DATA_URL, {
    params: { account_number: ACCOUNT_ID },
    headers: {
      'Accept'           : 'application/json, text/javascript, */*; q=0.01',
      'X-Requested-With' : 'XMLHttpRequest',
      'Referer'          : tradingPageUrl,
    },
  });

  const json = r.data;

  if (typeof json === 'string') {
    const preview = json.slice(0, 150).replace(/\s+/g, ' ');
    throw new Error(`Not authenticated — API returned HTML: ${preview}`);
  }
  if (!json || !json.success) {
    throw new Error(`API returned success:false — status ${r.status}, data: ${JSON.stringify(json).slice(0, 200)}`);
  }

  // Fetch account summary for requirements (best-effort, non-blocking)
  const reqs = await fetchRequirements(client);

  const chartData    = json.chart_data       || [];
  const adjData      = json.cash_adjustments || [];

  // Sort sessions oldest → newest
  const sessions = [...chartData].sort((a, b) =>
    String(a.TradeDate).localeCompare(String(b.TradeDate))
  );

  // Build adjustment map keyed by affected trading date
  const adjMap = {};
  for (const a of adjData) {
    const commentDate = String(a.comment || '').match(/(\d{1,2}[-\/]\d{1,2}[-\/]\d{4})/);
    const affectedDate = commentDate ? normDate(commentDate[1]) : normDate(a.TradeDate);
    if (affectedDate) {
      adjMap[affectedDate] = Math.round(((adjMap[affectedDate] || 0) + (a.amount || 0)) * 100) / 100;
    }
  }

  // Build entries with net P&L
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

  // ── Trailing drawdown ──────────────────────────────────────────────────────
  // APEX_DRAWDOWN_FLOOR: set this manually from Tradovate's "DRAWDOWN AUTO" column.
  // It only changes when the account hits a new EOD high watermark.
  // APEX_TRAILING_DRAWDOWN: the fixed trailing limit (e.g. 6500 for $250k PA).
  const trailingDrawdown = Number(process.env.APEX_TRAILING_DRAWDOWN || 6500);
  const highWatermarkCalc = chartData.reduce((max, s) => Math.max(max, s.AcctBal || 0), 0);
  // Use the env-pinned floor if provided (accurate), else estimate from session data
  const envFloor         = process.env.APEX_DRAWDOWN_FLOOR ? Number(process.env.APEX_DRAWDOWN_FLOOR) : null;
  const drawdownFloor    = envFloor != null ? envFloor : Math.round((highWatermarkCalc - trailingDrawdown) * 100) / 100;
  const highWatermark    = envFloor != null ? Math.round((envFloor + trailingDrawdown) * 100) / 100 : highWatermarkCalc;
  const drawdownCushion  = Math.round(((balanceNum || 0) - drawdownFloor) * 100) / 100;

  // ── Latest session ─────────────────────────────────────────────────────────
  const latestEntry = entries.length ? entries[entries.length - 1] : null;

  // ── Payout / eval progress ─────────────────────────────────────────────────
  // Fallbacks: known Legacy 250K values. Override via env vars if Apex changes them.
  const profitTarget      = reqs.profitTarget       || Number(process.env.APEX_PROFIT_TARGET    || 256600);
  const initialBalance    = reqs.initialBalance     || Number(process.env.APEX_INITIAL_BALANCE  || 250000);
  const minTradingDays    = reqs.minTradingDays      || Number(process.env.APEX_MIN_TRADING_DAYS || 8);
  const minProfitDays     = reqs.minProfitDays       || Number(process.env.APEX_MIN_PROFIT_DAYS  || 5);
  const minProfitThresh   = reqs.minProfitThreshold  || Number(process.env.APEX_MIN_PROFIT_THRESH|| 150);

  const daysWithFills     = entries.filter(e => e.fills > 0).length;
  const profitableDays    = entries.filter(e => e.pnl >= minProfitThresh).length;

  return {
    accountId  : ACCOUNT_ID,
    balance,
    totalProfit,
    status     : 'Active',
    entries,
    adjustments: adjData.map(a => ({
      date   : normDate(a.TradeDate),
      amount : Math.round((a.amount || 0) * 100) / 100,
      comment: a.comment,
    })),
    drawdown: {
      trailingLimit : trailingDrawdown,
      highWatermark : Math.round(highWatermark * 100) / 100,
      floor         : drawdownFloor,
      cushion       : drawdownCushion,
      currentBalance: Math.round((balanceNum || 0) * 100) / 100,
    },
    requirements: {
      profitTarget,
      initialBalance,
      minTradingDays,
      minProfitDays,
      minProfitThreshold: minProfitThresh,
    },
    progress: {
      currentBalance  : Math.round((balanceNum || 0) * 100) / 100,
      daysWithFills,
      profitableDays,
    },
    latestSession: latestEntry,
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
    const tradingPageUrl = `${BASE}/member/account/trading?account=${ACCOUNT_ID}`;
    await client.get(tradingPageUrl);
    const r = await client.get(DATA_URL, {
      params: { account_number: ACCOUNT_ID },
      headers: {
        'Accept'           : 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With' : 'XMLHttpRequest',
        'Referer'          : tradingPageUrl,
      },
    });
    const isJson = typeof r.data === 'object';
    res.json({
      status        : r.status,
      isJson,
      success       : isJson ? r.data?.success : false,
      sessionCount  : isJson ? (r.data?.chart_data?.length ?? 0) : 0,
      adjCount      : isJson ? (r.data?.cash_adjustments?.length ?? 0) : 0,
      preview       : isJson ? r.data : String(r.data).slice(0, 300),
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
