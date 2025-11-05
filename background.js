// background.js — PhishSpector (advanced header + history + caching)
// Replace BACKEND_URL with your backend endpoint if different
const BACKEND_URL = "http://127.0.0.1:5000";

console.log("[PhishSpector-bg] starting background worker");

// --------------------
// Configuration (tune these)
// --------------------
const CACHE_TTL_MS = 1000 * 60 * 10; // 10 minutes for header cache
const QUERY_CACHE_TTL_MS = 1000 * 60 * 5; // 5 minutes for fuzzy caches

// Weights for final ensemble (sum doesn't have to be 1 but interpret proportionally)
const WEIGHTS = {
  local: 0.25,   // content.js heuristic
  ml: 0.50,      // backend ML
  header: 0.20,  // inverse of header trust -> suspicion
  history: 0.05  // small extra adjustment from user history (applied as trust)
};

// How many trust points to give for user-marked safe senders (added to header trust calculation)
const TRUST_BOOST_FROM_HISTORY = 25; // 0-100 scale

// Header trust mapping (per-pass points)
const HEADER_TRUST_POINTS = {
  spf_pass: 40,
  dkim_pass: 40,
  dmarc_pass: 20,
  spf_fail: -40,
  dkim_fail: -40,
  dmarc_fail: -20
};

// Minimal thresholds
const MIN_ML_SCORE = 0;
const MAX_SCORE = 100;

// --------------------
// In-memory caches
// --------------------
const HEADER_CACHE = new Map(); // key: messageId or queryKey -> { ts, data }
const QUERY_CACHE = new Map();  // key: searchKey -> { ts, data }

// --------------------
// Utils: OAuth & Gmail API
// --------------------
async function getGmailToken(interactive = false) {
  return new Promise((resolve, reject) => {
    try {
      chrome.identity.getAuthToken({ interactive }, (token) => {
        if (chrome.runtime.lastError || !token) {
          const err = chrome.runtime.lastError || new Error("No token");
          return reject(err);
        }
        resolve(token);
      });
    } catch (e) {
      reject(e);
    }
  });
}

async function gmailApi(path, token, opts = {}) {
  const url = `https://www.googleapis.com/gmail/v1/users/me${path}`;
  const res = await fetch(url, {
    method: opts.method || "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Gmail API ${res.status}: ${text}`);
  }
  return res.json();
}

// --------------------
// Parse Authentication-Results
// --------------------
function parseAuthResults(authHeader) {
  if (!authHeader || typeof authHeader !== "string") return { spf: null, dkim: null, dmarc: null, raw: "" };
  const lower = authHeader.toLowerCase();
  return {
    spf: lower.includes("spf=pass") ? "pass" : (lower.includes("spf=fail") ? "fail" : null),
    dkim: lower.includes("dkim=pass") ? "pass" : (lower.includes("dkim=fail") ? "fail" : null),
    dmarc: lower.includes("dmarc=pass") ? "pass" : (lower.includes("dmarc=fail") ? "fail" : null),
    raw: authHeader
  };
}

// Build header trust points (higher = more trusted)
function headerTrustFromParsed(parsed) {
  if (!parsed) return 50; // neutral mid value
  let trust = 50; // start neutral at 50/100
  if (parsed.spf === "pass") trust += HEADER_TRUST_POINTS.spf_pass;
  if (parsed.spf === "fail") trust += HEADER_TRUST_POINTS.spf_fail;
  if (parsed.dkim === "pass") trust += HEADER_TRUST_POINTS.dkim_pass;
  if (parsed.dkim === "fail") trust += HEADER_TRUST_POINTS.dkim_fail;
  if (parsed.dmarc === "pass") trust += HEADER_TRUST_POINTS.dmarc_pass;
  if (parsed.dmarc === "fail") trust += HEADER_TRUST_POINTS.dmarc_fail;
  // clamp
  trust = Math.max(0, Math.min(100, trust));
  return trust;
}

// --------------------
// Envelope vs display-from mismatch detection
// --------------------
function domainFromAddress(addr) {
  if (!addr || typeof addr !== "string") return null;
  const m = addr.match(/@([^>\s]+)/);
  if (m && m[1]) return m[1].toLowerCase();
  return null;
}

function displayNameAndEmail(fromHeader) {
  // returns { displayName, email }
  if (!fromHeader) return { displayName: "", email: "" };
  // Gmail typically shows 'Name <email@domain>'
  const m = fromHeader.match(/(.*)<([^>]+)>/);
  if (m) return { displayName: (m[1] || "").trim(), email: (m[2] || "").trim() };
  // otherwise attempt to extract first email-looking token
  const e = (fromHeader.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i) || [null])[0];
  return { displayName: fromHeader.replace(e || "", "").trim(), email: e || "" };
}

// --------------------
// Google relay detection heuristics
// --------------------
function detectGoogleRelay(headers) {
  if (!headers || typeof headers !== "object") return false;
  // Look for common Google-added headers
  const keys = Object.keys(headers).map(k => k.toLowerCase());
  if (keys.some(k => k.includes("x-google-smtp-source"))) return true;
  if (keys.some(k => k.includes("x-google")) ) return true;
  if (keys.some(k => k.includes("x-gm-"))) return true;
  if (keys.some(k => k.includes("arc-seal"))) return true;
  if (headers['Delivered-To'] || headers['delivered-to']) return true;
  return false;
}

// --------------------
// Caching helpers
// --------------------
function cacheSet(cacheMap, key, data, ttl) {
  cacheMap.set(key, { ts: Date.now(), data, ttl });
}

function cacheGet(cacheMap, key) {
  const v = cacheMap.get(key);
  if (!v) return null;
  if ((Date.now() - v.ts) > (v.ttl || CACHE_TTL_MS)) {
    cacheMap.delete(key);
    return null;
  }
  return v.data;
}

// --------------------
// Gmail metadata fetch routines
// --------------------
async function findMessageId(token, { fromText, subjectText, snippetText }) {
  // Build a safe query
  const safe = (s) => (s || "").replace(/"/g, '\\"').trim();
  const qParts = [];
  if (subjectText) qParts.push(`subject:"${safe(subjectText)}"`);
  if (fromText) qParts.push(`from:"${safe(fromText)}"`);
  qParts.push("newer_than:14d");
  const q = qParts.join(' ');
  const list = await gmailApi(`/messages?q=${encodeURIComponent(q)}&maxResults=5`, token);
  if (!list.messages || list.messages.length === 0) return null;
  return list.messages[0].id;
}

async function fetchMessageMetadata(token, messageId) {
  // metadata with necessary headers
  const msg = await gmailApi(`/messages/${messageId}?format=metadata&metadataHeaders=From&metadataHeaders=Return-Path&metadataHeaders=Authentication-Results&metadataHeaders=Delivered-To&metadataHeaders=Received&metadataHeaders=X-Google-Smtp-Source`, token);
  // Convert header array to object
  const headers = {};
  if (msg && msg.payload && Array.isArray(msg.payload.headers)) {
    msg.payload.headers.forEach(h => { headers[h.name] = h.value; });
  }
  return { headers, messageId };
}

// --------------------
// Trusted sender history (chrome.storage)
// --------------------
function addTrustedSenderDomain(domain) {
  if (!domain) return;
  chrome.storage.local.get({ trustedSenders: {} }, (res) => {
    const map = res.trustedSenders || {};
    const now = Date.now();
    if (!map[domain]) map[domain] = { count: 0, last: now };
    map[domain].count = (map[domain].count || 0) + 1;
    map[domain].last = now;
    chrome.storage.local.set({ trustedSenders: map }, () => {
      console.log("[PhishSpector-bg] trusted sender incremented", domain, map[domain]);
    });
  });
}

function getTrustedSenderBoost(domain) {
  return new Promise((resolve) => {
    if (!domain) return resolve(0);
    chrome.storage.local.get({ trustedSenders: {} }, (res) => {
      const map = res.trustedSenders || {};
      const rec = map[domain];
      if (!rec) return resolve(0);
      // simple boost logic: more count -> more trust, but cap it
      const boost = Math.min(TRUST_BOOST_FROM_HISTORY, rec.count * 5);
      resolve(boost);
    });
  });
}

// --------------------
// Message handlers (chrome.runtime.onMessage)
// --------------------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (!msg || !msg.type) return sendResponse({ ok: false, error: "no_type" });

      // --------------------
      // interactive auth from popup
      // --------------------
      if (msg.type === "interactive_auth") {
        try {
          const token = await getGmailToken(true);
          return sendResponse({ ok: !!token });
        } catch (e) {
          return sendResponse({ ok: false, error: String(e) });
        }
      }

      // --------------------
      // get_headers - return parsed header signals + trustBoost + messageId
      // --------------------
      if (msg.type === "get_headers") {
        const payload = msg.payload || {};
        // try quick cache by a query key (subject+from+snippet)
        const queryKey = `${payload.fromText || ''}||${payload.subjectText || ''}||${payload.snippetText || ''}`;
        const cached = cacheGet(QUERY_CACHE, queryKey);
        if (cached) {
          return sendResponse({ ok: true, ...cached });
        }

        // try to get token (non-interactive)
        let token = null;
        try { token = await getGmailToken(false); } catch (e) { token = null; }

        if (!token) {
          // cannot fetch headers without token
          return sendResponse({ ok: false, error: "no_token" });
        }

        // find message id
        const msgId = await findMessageId(token, payload);
        if (!msgId) {
          return sendResponse({ ok: false, error: "no_message" });
        }

        // check header cache by message id
        const headerCached = cacheGet(HEADER_CACHE, msgId);
        if (headerCached) {
          cacheSet(QUERY_CACHE, queryKey, headerCached, QUERY_CACHE_TTL_MS);
          return sendResponse({ ok: true, ...headerCached });
        }

        // fetch metadata
        const { headers, messageId } = await fetchMessageMetadata(token, msgId);
        const authRaw = headers['Authentication-Results'] || headers['Authentication-results'] || headers['Authentication-Results:'] || '';
        const parsed = parseAuthResults(authRaw);
        let trust = headerTrustFromParsed(parsed); // 0..100

        // envelope vs display-from mismatch
        const fromHeader = headers['From'] || headers['from'] || payload.fromText || "";
        const returnPath = headers['Return-Path'] || headers['return-path'] || headers['Return-Path:'] || "";
        const { email: fromEmail } = displayNameAndEmail(fromHeader || "");
        const envDomain = domainFromAddress(returnPath) || domainFromAddress(fromEmail);
        const displayDomain = domainFromAddress(fromEmail);
        let envelopeMismatch = false;
        if (envDomain && displayDomain && envDomain !== displayDomain) {
          // mismatch increases suspicion -> decrease trust
          envelopeMismatch = true;
          trust = Math.max(0, trust - 30);
        }

        // Google relay detection (gives more trust)
        const googleRelay = detectGoogleRelay(headers);
        if (googleRelay) trust = Math.min(100, trust + 20);

        // add user history boost
        const domain = displayDomain || envDomain;
        const historyBoost = await getTrustedSenderBoost(domain);
        if (historyBoost) {
          trust = Math.min(100, trust + historyBoost);
        }

        const result = {
          messageId,
          headers,
          parsed,
          trustBoost: trust,
          envelopeMismatch,
          googleRelay
        };

        // cache results
        cacheSet(HEADER_CACHE, messageId, result, CACHE_TTL_MS);
        cacheSet(QUERY_CACHE, queryKey, result, QUERY_CACHE_TTL_MS);

        return sendResponse({ ok: true, ...result });
      }

      // --------------------
      // get_scores - return combined final score (expects payload.localScore optional)
      // --------------------
      if (msg.type === "get_scores") {
        const payload = msg.payload || {};
        const localScore = (typeof payload.localScore === "number") ? payload.localScore : (payload.local || 50);

        // Attempt to call backend ML (best-effort)
        let ml_score = null;
        try {
          const text = `${payload.fromText || ''} ${payload.subjectText || ''} ${payload.snippetText || ''}`.trim();
          const resp = await fetch(`${BACKEND_URL}/predict`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text })
          });
          const json = await resp.json();
          ml_score = json.ml_score || json.score || null;
          if (typeof ml_score === "string") ml_score = parseFloat(ml_score);
        } catch (e) {
          // fallback: null -> will use localScore as proxy
          ml_score = null;
          console.warn("[PhishSpector-bg] ML backend call failed", e && e.message);
        }

        // Try to fetch header trust (non-interactive)
        let headerTrust = 50; // neutral
        try {
          // attempt to locate message id using provided payload
          let token = null;
          try { token = await getGmailToken(false); } catch (e) { token = null; }
          if (token) {
            const msgId = await findMessageId(token, payload);
            if (msgId) {
              const cached = cacheGet(HEADER_CACHE, msgId);
              if (cached) {
                headerTrust = cached.trustBoost || headerTrust;
              } else {
                try {
                  const { headers, messageId } = await fetchMessageMetadata(token, msgId);
                  const parsed = parseAuthResults(headers['Authentication-Results'] || '');
                  headerTrust = headerTrustFromParsed(parsed);
                  // google relay and envelope mismatch adjustments:
                  if (detectGoogleRelay(headers)) headerTrust = Math.min(100, headerTrust + 20);
                  const { email: fromEmail } = displayNameAndEmail(headers['From'] || payload.fromText || "");
                  const envDomain = domainFromAddress(headers['Return-Path'] || '') || domainFromAddress(fromEmail);
                  const displayDomain = domainFromAddress(fromEmail);
                  if (envDomain && displayDomain && envDomain !== displayDomain) headerTrust = Math.max(0, headerTrust - 30);
                  // history
                  const domain = displayDomain || envDomain;
                  const historyBoost = await getTrustedSenderBoost(domain);
                  if (historyBoost) headerTrust = Math.min(100, headerTrust + historyBoost);
                  // cache
                  cacheSet(HEADER_CACHE, msgId, { messageId: msgId, headers, parsed, trustBoost: headerTrust }, CACHE_TTL_MS);
                } catch (e) {
                  console.warn("[PhishSpector-bg] header parse fallback error", e && e.message);
                }
              }
            }
          }
        } catch (e) {
          console.warn("[PhishSpector-bg] header trust attempt error", e && e.message);
        }

        // Build final ensemble
        const mlVal = (typeof ml_score === "number") ? ml_score : localScore;
        const headerSuspicion = 100 - (headerTrust || 50); // convert trust->suspicion
        // HISTORY is handled already via headerTrust boost
        const final = Math.round(
          (localScore * (WEIGHTS.local || 0)) +
          (mlVal * (WEIGHTS.ml || 0)) +
          (headerSuspicion * (WEIGHTS.header || 0))
        );

        const finalScore = Math.max(0, Math.min(MAX_SCORE, final));

        return sendResponse({
          ok: true,
          localScore,
          ml_score: mlVal,
          headerTrust,
          final_score: finalScore
        });
      }

      // --------------------
      // feedback — store local & optionally update trusted senders
      // --------------------
      if (msg.type === "feedback") {
        try {
          const fb = msg;
          // store feedback array
          chrome.storage.local.get({ phishFeedback: [] }, (res) => {
            const arr = res.phishFeedback || [];
            arr.push({ ts: Date.now(), label: fb.label, detail: fb.detail });
            chrome.storage.local.set({ phishFeedback: arr }, () => {
              console.log("[PhishSpector-bg] saved feedback", fb.label);
            });
          });

          // If user marked safe, add trusted sender history
          if (fb.label === "safe" && fb.detail && fb.detail.fromText) {
            const { email } = displayNameAndEmail(fb.detail.fromText);
            const dom = domainFromAddress(email);
            if (dom) addTrustedSenderDomain(dom);
          }

          // send to backend best-effort
          try {
            fetch(`${BACKEND_URL}/feedback`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ ts: Date.now(), label: fb.label, detail: fb.detail })
            }).catch(e => console.warn("[PhishSpector-bg] feedback post failed", e && e.message));
          } catch (e) { console.warn("[PhishSpector-bg] feedback send catch", e && e.message); }

          return sendResponse({ ok: true });
        } catch (e) {
          console.warn("[PhishSpector-bg] feedback handler error", e && e.message);
          return sendResponse({ ok: false, error: String(e) });
        }
      }

      // unknown type
      return sendResponse({ ok: false, error: "unknown_type" });
    } catch (err) {
      console.error("[PhishSpector-bg] onMessage top error", err && err.message);
      try { sendResponse({ ok: false, error: String(err) }); } catch {}
    }
  })();
  return true; // keep channel open for async responses
});
