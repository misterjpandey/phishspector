// service_worker.js (module)
console.log('[PhishSpector] service worker started');

const BACKEND_BASE = 'http://localhost:5000'; // change in production to HTTPS endpoint

// helper: get OAuth token via chrome.identity
async function getToken(interactive = false) {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({interactive}, (token) => {
      if (chrome.runtime.lastError) {
        console.warn('[PhishSpector] getAuthToken error', chrome.runtime.lastError.message);
        resolve(null);
      } else {
        resolve(token);
      }
    });
  });
}

// Search Gmail messages by from/subject text to find a likely message ID
async function searchMessageId(token, {fromText, subjectText}) {
  try {
    const qParts = [];
    if (fromText) qParts.push(`from:${sanitizeForQuery(fromText)}`);
    if (subjectText) qParts.push(`subject:${sanitizeForQuery(subjectText)}`);
    const q = encodeURIComponent(qParts.join(' '));
    const url = `https://www.googleapis.com/gmail/v1/users/me/messages?q=${q}&maxResults=3`;
    const resp = await fetch(url, {headers: {Authorization: `Bearer ${token}`}});
    if (!resp.ok) {
      console.warn('[PhishSpector] Gmail search failed', await resp.text());
      return null;
    }
    const data = await resp.json();
    if (data.messages && data.messages.length > 0) {
      return data.messages[0].id;
    }
    return null;
  } catch (e) {
    console.warn('[PhishSpector] searchMessageId error', e);
    return null;
  }
}

function sanitizeForQuery(s) {
  // basic sanitize: remove quotes and newlines
  return (s || '').replace(/["']/g, '').replace(/\n/g, ' ');
}

async function getMessageHeaders(token, messageId) {
  try {
    const url = `https://www.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=metadata&metadataHeaders=From&metadataHeaders=Return-Path&metadataHeaders=Authentication-Results&metadataHeaders=Received-SPF`;
    const resp = await fetch(url, {headers: {Authorization: `Bearer ${token}`}});
    if (!resp.ok) {
      console.warn('[PhishSpector] getMessageHeaders failed', await resp.text());
      return null;
    }
    const data = await resp.json();
    const headers = {};
    (data.payload && data.payload.headers || []).forEach(h => { headers[h.name] = h.value; });
    return headers;
  } catch (e) {
    console.warn('[PhishSpector] getMessageHeaders error', e);
    return null;
  }
}

// Basic header analysis to build a summary & simple header_score
function analyzeHeaders(headers) {
  if (!headers) return {summary: 'no headers', score: 0};
  let score = 0;
  let summaryParts = [];

  const auth = headers['Authentication-Results'] || '';
  if (auth.toLowerCase().includes('dkim=pass')) { summaryParts.push('DKIM: pass'); score -= 10; } else if (auth.toLowerCase().includes('dkim=fail')) { summaryParts.push('DKIM: fail'); score += 20; }

  if (auth.toLowerCase().includes('spf=pass')) { summaryParts.push('SPF: pass'); score -= 10; } else if (auth.toLowerCase().includes('spf=fail')) { summaryParts.push('SPF: fail'); score += 25; }

  const returnPath = headers['Return-Path'] || '';
  const from = headers['From'] || '';
  if (returnPath && from && !from.includes(returnPath.replace(/<|>/g, '').split('@').slice(-1))) {
    summaryParts.push('From/Return-Path mismatch');
    score += 15;
  }

  return {summary: summaryParts.join('; ') || 'no auth info', score: Math.max(0, Math.min(100, score))};
}

// call backend to check URLs and ML predict
async function callBackendAnalyze(urls = [], features = {}) {
  try {
    // check first url only for demo
    const urlToCheck = urls[0];
    let url_score;
    if (urlToCheck) {
      const resp = await fetch(`${BACKEND_BASE}/check_url`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({url: urlToCheck})
      });
      const j = await resp.json();
      url_score = j.reputation_score;
    }

    // ML predict
    const resp2 = await fetch(`${BACKEND_BASE}/predict`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({features})
    });
    const j2 = await resp2.json();
    const ml_score = j2.ml_score;

    return {url_score, ml_score};
  } catch (e) {
    console.warn('[PhishSpector] callBackendAnalyze error', e);
    return {url_score: undefined, ml_score: undefined};
  }
}

// extract first URL from snippet
function extractUrlsFromText(s) {
  if (!s) return [];
  const m = s.match(/https?:\/\/[^\s)]+/g);
  return m || [];
}

// Combine signals into final score
function combineScores(localScore, headerScore, urlScore, mlScore) {
  // Weighted combination (demo weights — tune for final)
  const weights = {local: 0.35, header: 0.25, url: 0.2, ml: 0.2};
  const a = localScore || 0;
  const b = headerScore || 0;
  const c = (urlScore !== undefined ? urlScore : 50); // neutral if undefined
  const d = (mlScore !== undefined ? mlScore : 50);
  const combined = a*weights.local + b*weights.header + c*weights.url + d*weights.ml;
  return Math.round(Math.max(0, Math.min(100, combined)));
}

// Handle messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === 'get_scores') {
    handleGetScores(message.payload).then(r => sendResponse(r)).catch(e => sendResponse(null));
    return true; // keep channel open
  }
});

async function handleGetScores(payload) {
  // 1. get OAuth token (non-interactive first)
  let token = await getToken(false);
  if (!token) {
    // attempt interactive
    token = await getToken(true);
  }
  // 2. try to find message ID via search
  let messageId = null;
  if (token) {
    messageId = await searchMessageId(token, payload);
  }

  let headers = null, headerAnalysis = null;
  if (messageId && token) {
    headers = await getMessageHeaders(token, messageId);
    headerAnalysis = analyzeHeaders(headers);
  }

  // 3. extract URL(s) from snippet
  const urls = (payload.snippetText ? payload.snippetText.match(/https?:\/\/[^\s)]+/g) : []) || [];
  // 4. call backend to get url and ml scores
  const features = { /* minimal features for demo */ local_subject: payload.subjectText || '', from: payload.fromText || '' };
  const backendRes = await callBackendAnalyze(urls, features);

  const final_score = combineScores( computeLocalScoreForBackground(payload), (headerAnalysis && headerAnalysis.score) || 0, backendRes.url_score, backendRes.ml_score );

  return {
    headers,
    header_summary: headerAnalysis ? headerAnalysis.summary : null,
    header_score: headerAnalysis ? headerAnalysis.score : 0,
    url_score: backendRes.url_score,
    ml_score: backendRes.ml_score,
    final_score
  };
}

// compute local heuristic again on background (basic copy of content heuristic)
function computeLocalScoreForBackground({fromText='', subjectText='', snippetText='', rowText=''}) {
  let score = 0;
  const combined = (subjectText + ' ' + snippetText + ' ' + rowText).toLowerCase();
  const suspiciousWords = ['verify','verification','urgent','action required','reset','password','account suspended','confirm','click','immediately','limited time','wire transfer','payment required','security alert','invoice'];
  suspiciousWords.forEach(w => { if (combined.includes(w)) score += 8; });

  if (fromText) {
    const emailLike = fromText.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
    const namePart = fromText.replace(emailLike ? emailLike[0] : '', '').trim();
    if (emailLike && namePart.length > 0 && /@/.test(namePart)) score += 8;
    if (/[^a-zA-Z0-9\s\.\-\,]/.test(fromText)) score += 6;
    if (fromText.length <= 2) score += 10;
  }

  const linkCount = (snippetText.match(/https?:\/\//g) || []).length;
  if (linkCount >= 1) score += 10 * Math.min(linkCount, 3);

  const brandWords = ['google','paypal','amazon','microsoft','apple','bank'];
  brandWords.forEach(brand => { if (combined.includes(brand) && !(fromText||'').toLowerCase().includes(brand)) score += 12; });

  const exclam = (subjectText.match(/!/g) || []).length;
  if (exclam > 0) score += Math.min(6, exclam * 2);
  const uppercaseShare = (subjectText.replace(/[^A-Z]/g, '').length) / Math.max(1, subjectText.length || 1);
  if (uppercaseShare > 0.35) score += 10;

  score = Math.min(100, score + Math.floor(Math.random() * 5));
  return Math.round(score);
}

// feedback listener (example, logs only)
self.addEventListener('message', (event) => {
  const data = event.data;
  if (data && data.type === 'feedback') {
    console.log('[PhishSpector] feedback received', data.label, data.detail);
    // In a full implementation we'd POST to backend to store label
  }
});
