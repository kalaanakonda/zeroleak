// ZEROLEAK — live paper system prototype ("glass room" build)
// Everything security-relevant is observable and independently verifiable:
//   1. Paper does not exist before T-0 (seed is born at T-0, not stored).
//   2. Real Shamir 5-of-9 secret sharing simulates the officials' ceremony.
//   3. Public randomness (drand) is mixed into the seed — and must be from a
//      round produced AFTER the commitment was published, so not even the
//      ceremony secret holder could compute the paper before T-0.
//   4. Hash-chained audit ledger — every event is tamper-evident.
//   5. Commit-reveal: fairness receipt published before, provable after.
//   6. Per-center invisible watermarks make every copy trace its leaker.
//
// Zero dependencies. Run: node server.js  →  http://localhost:4870
//
// Demo honesty note: a real deployment uses dealerless distributed key
// generation across nine independent devices. This demo simulates all nine
// on one server so you can watch the protocol; the math is the real thing.

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { fork } = require('child_process');

const PORT = 4870;
const BANK = require('./questionbank.js');

const CENTERS = [
  { id: 'C101', name: 'Delhi — Kendriya Vidyalaya, RK Puram' },
  { id: 'C202', name: 'Patna — St. Xavier’s High School' },
  { id: 'C303', name: 'Kota — Govt. Sr. Sec. School, Vigyan Nagar' },
];

const OFFICIALS = [
  { id: 1, name: 'Retd. Justice R. Menon', org: 'Supreme Court (retd.)', city: 'New Delhi' },
  { id: 2, name: 'Prof. A. Krishnan', org: 'IIT Delhi', city: 'Delhi' },
  { id: 3, name: 'Dr. S. Bhattacharya', org: 'AIIMS', city: 'Kolkata' },
  { id: 4, name: 'Smt. N. Deshpande', org: 'CAG Office', city: 'Mumbai' },
  { id: 5, name: 'Shri V. Reddy', org: 'State Education Board', city: 'Hyderabad' },
  { id: 6, name: 'Prof. L. Sharma', org: 'IISc', city: 'Bengaluru' },
  { id: 7, name: 'Dr. F. Qureshi', org: 'Jamia Millia Islamia', city: 'Delhi' },
  { id: 8, name: 'Smt. G. Nair', org: 'Election Commission (retd.)', city: 'Kochi' },
  { id: 9, name: 'Shri T. Boro', org: 'State Education Board', city: 'Guwahati' },
];
const THRESHOLD = 5;

// Countdown must exceed one drand period (30s) so the beacon round used at
// T-0 is guaranteed to have been produced AFTER the commitment existed.
const MIN_SECONDS = 35;

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function hmac(key, msg) { return crypto.createHmac('sha256', key).update(msg).digest('hex'); }

// --- Real Shamir secret sharing over GF(p), p = 2^256 - 189 (prime) --------
const P = (1n << 256n) - 189n;

function randField() {
  return BigInt('0x' + crypto.randomBytes(40).toString('hex')) % P;
}
function modpow(b, e, m) {
  let r = 1n; b %= m;
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
}
function modinv(a) { return modpow(((a % P) + P) % P, P - 2n, P); }

function shamirSplit(secret, n, k) {
  const coeffs = [secret];
  for (let i = 1; i < k; i++) coeffs.push(randField());
  const shares = [];
  for (let x = 1n; x <= BigInt(n); x++) {
    let y = 0n, xp = 1n;
    for (const c of coeffs) { y = (y + c * xp) % P; xp = (xp * x) % P; }
    shares.push({ x: Number(x), y: y.toString(16).padStart(64, '0') });
  }
  return shares;
}

function shamirCombine(shares) {
  let secret = 0n;
  for (const si of shares) {
    let num = 1n, den = 1n;
    const xi = BigInt(si.x);
    for (const sj of shares) {
      if (sj.x === si.x) continue;
      const xj = BigInt(sj.x);
      num = (num * ((P - xj) % P)) % P;
      den = (den * (((xi - xj) % P + P) % P)) % P;
    }
    secret = (secret + BigInt('0x' + si.y) * num % P * modinv(den)) % P;
  }
  return secret.toString(16).padStart(64, '0');
}

// Deterministic PRNG from a hex seed. 16-bit draws to keep Fisher-Yates
// index bias negligible. Verifiers reproduce this exactly in the browser.
function makeRng(seedHex) {
  let state = Buffer.from(seedHex, 'hex');
  let pool = [], i = 0;
  return function rand() {
    if (i + 2 > pool.length) {
      state = crypto.createHash('sha256').update(state).digest();
      pool = Array.from(state); i = 0;
    }
    const v = (pool[i] << 8) | pool[i + 1];
    i += 2;
    return v / 65536;
  };
}
function shuffle(arr, rng) {
  const a = arr.slice();
  for (let k = a.length - 1; k > 0; k--) {
    const j = Math.floor(rng() * (k + 1));
    [a[k], a[j]] = [a[j], a[k]];
  }
  return a;
}

// ---------------------------------------------------------------------------
// Paper generation — only possible once the seed exists (after T-0)
// ---------------------------------------------------------------------------
const PER_SUBJECT = 5;

function generatePaper(seed) {
  const rng = makeRng(seed);
  const paper = [];
  for (const subject of ['Physics', 'Chemistry', 'Biology']) {
    const qs = shuffle(BANK.filter(q => q.subject === subject), rng).slice(0, PER_SUBJECT);
    for (const q of qs) {
      const order = shuffle([0, 1, 2, 3], rng);
      paper.push({ subject, text: q.text, options: order.map(x => q.options[x]) });
    }
  }
  return paper;
}

// Invisible watermark: zero-width chars encode the center ID in the text.
const ZW0 = '​', ZW1 = '‌', ZWS = '‍';
function watermarkText(text, centerId) {
  let bits = '';
  for (const ch of centerId) bits += ch.charCodeAt(0).toString(2).padStart(8, '0');
  const mark = ZWS + bits.split('').map(b => (b === '1' ? ZW1 : ZW0)).join('');
  const idx = text.indexOf(' ');
  return idx === -1 ? text + mark : text.slice(0, idx) + mark + text.slice(idx);
}
function traceWatermark(text) {
  const m = text.indexOf(ZWS);
  if (m === -1) return null;
  let bits = '';
  for (const ch of text.slice(m + 1)) {
    if (ch === ZW0) bits += '0';
    else if (ch === ZW1) bits += '1';
    else if (bits.length >= 8) break;
  }
  let out = '';
  for (let i = 0; i + 8 <= bits.length; i += 8) out += String.fromCharCode(parseInt(bits.slice(i, i + 8), 2));
  return out || null;
}

function paperForCenter(seed, centerId) {
  const base = generatePaper(seed);
  const rng = makeRng(hmac(seed, 'order:' + centerId));
  const bySubject = {};
  for (const q of base) (bySubject[q.subject] ||= []).push(q);
  const ordered = [];
  for (const s of ['Physics', 'Chemistry', 'Biology']) ordered.push(...shuffle(bySubject[s], rng));
  return ordered.map((q, i) => ({ n: i + 1, subject: q.subject, text: watermarkText(q.text, centerId), options: q.options }));
}

// ---------------------------------------------------------------------------
// Exam state + hash-chained audit ledger
// ---------------------------------------------------------------------------
let exam = null;

// Events are hash-chained over a JSON preimage (field-malleability-safe).
// Guarded by exam identity so a stale timer can never write into a newer
// exam's ledger.
function logEvent(ex, type, detail) {
  if (!ex || exam !== ex) return;
  const prev = ex.events.length ? ex.events[ex.events.length - 1].hash : 'GENESIS';
  const n = ex.events.length;
  const t = Date.now();
  const hash = sha256(JSON.stringify([n, t, type, detail, prev]));
  ex.events.push({ n, t, type, detail, prev, hash });
}

function clearTimers() {
  if (exam) for (const t of exam.timers) clearTimeout(t);
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// drand default chain (League of Entropy): 30s period. Round r is produced
// at genesis + (r-1)*period — deterministic, so freshness is checkable by
// anyone. We fetch chain info rather than hardcoding it.
let drandInfo = null;
async function fetchJson(u, timeoutMs) {
  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), timeoutMs || 2500);
  try { return await (await fetch(u, { signal: ctrl.signal })).json(); }
  finally { clearTimeout(to); }
}
async function fetchBeacon(notBeforeMs) {
  try {
    if (!drandInfo) drandInfo = await fetchJson('https://api.drand.sh/info');
    // Take the latest round; if it predates the commitment (possible only
    // with very short countdowns or a stalled beacon), wait for a fresh one.
    for (let tries = 0; tries < 15; tries++) {
      const d = await fetchJson('https://api.drand.sh/public/latest');
      const roundTime = (drandInfo.genesis_time + (d.round - 1) * drandInfo.period) * 1000;
      if (roundTime >= notBeforeMs) {
        return {
          source: 'drand', round: d.round, randomness: d.randomness, roundTime,
          chain: { genesis_time: drandInfo.genesis_time, period: drandInfo.period },
          url: 'https://api.drand.sh/public/' + d.round,
        };
      }
      await sleep(3000);
    }
    throw new Error('no fresh round');
  } catch {
    const randomness = crypto.randomBytes(32).toString('hex');
    return { source: 'local-fallback (drand unreachable)', round: null, randomness, roundTime: null, chain: null, url: null };
  }
}

function scheduleExam(seconds) {
  clearTimers();
  const secs = Math.max(MIN_SECONDS, Math.min(600, seconds || 40));
  const scheduledAt = Date.now();
  const id = 'NEET-UG-' + scheduledAt;
  const t0 = scheduledAt + secs * 1000;
  const bankHash = sha256(JSON.stringify(BANK));

  // The ceremony secret. Demo note: dealt here on one server so the protocol
  // is watchable; production replaces this with dealerless DKG on 9 devices.
  const secretHex = randField().toString(16).padStart(64, '0');
  const shares = shamirSplit(BigInt('0x' + secretHex), OFFICIALS.length, THRESHOLD);
  const shareCommitments = shares.map(s => sha256(s.y));
  const secretHash = sha256(secretHex);

  // Fairness receipt: published NOW, binds everything, reveals nothing.
  const commitment = sha256(id + '|' + t0 + '|' + scheduledAt + '|' + bankHash + '|' + secretHash + '|' + shareCommitments.join(','));

  // Two random officials' devices are "offline" — 5-of-9 shrugs it off.
  const offline = new Set();
  while (offline.size < 2) offline.add(1 + Math.floor(Math.random() * OFFICIALS.length));

  const ex = exam = {
    id, t0, scheduledAt, bankHash, secretHex, secretHash, shares, shareCommitments, commitment,
    officials: OFFICIALS.map(o => ({ ...o, status: offline.has(o.id) ? 'offline' : 'waiting', submittedAt: null })),
    events: [], timers: [], delivered: {}, seed: null, beacon: null, combinedSecret: null,
  };

  logEvent(ex, 'exam-scheduled', `${id} · unlock at T-0 in ${secs}s · ${CENTERS.length} centers`);
  logEvent(ex, 'commitment-published', `fairness receipt ${commitment.slice(0, 24)}… (binds bank + ceremony + timing, reveals nothing)`);
  logEvent(ex, 'fragment-commitments-published', `9 fragment fingerprints published — fragments themselves stay sealed`);
  for (const o of ex.officials) if (o.status === 'offline') logEvent(ex, 'official-offline', `${o.name} (${o.org}, ${o.city}) — device unreachable`);

  // Online officials submit their fragments in the final seconds before T-0.
  const windowMs = Math.min(20000, secs * 1000 * 0.5);
  for (const o of ex.officials) {
    if (o.status === 'offline') continue;
    const at = t0 - 400 - Math.random() * windowMs;
    ex.timers.push(setTimeout(() => {
      if (exam !== ex || o.submittedAt) return;
      o.status = 'submitted'; o.submittedAt = Date.now();
      const count = ex.officials.filter(x => x.status === 'submitted').length;
      logEvent(ex, 'fragment-submitted', `${o.name} (${o.org}, ${o.city}) — fragment ${count} of ${THRESHOLD} needed`);
      if (count === THRESHOLD) logEvent(ex, 'threshold-reached', `${THRESHOLD} fragments in — key can be born at T-0`);
    }, Math.max(0, at - Date.now())));
  }

  // At T-0: combine fragments, mix in a beacon round produced strictly after
  // the commitment, derive the seed. Every await is followed by a staleness
  // guard — a reschedule mid-fetch must never touch the newer exam.
  ex.timers.push(setTimeout(async () => {
    if (exam !== ex) return;
    const submitted = ex.officials.filter(o => o.status === 'submitted');
    const used = ex.shares.filter(s => submitted.some(o => o.id === s.x)).slice(0, THRESHOLD);
    ex.combinedSecret = shamirCombine(used);
    logEvent(ex, 'secret-combined', `${used.length} fragments (officials ${used.map(s => s.x).join(', ')}) → ceremony secret reconstructed`);
    const beacon = await fetchBeacon(ex.scheduledAt);
    if (exam !== ex) return;
    ex.beacon = beacon;
    logEvent(ex, 'beacon-acquired', beacon.source === 'drand'
      ? `drand round ${beacon.round} (produced ${new Date(beacon.roundTime).toISOString()}, after the receipt) · ${beacon.randomness.slice(0, 24)}…`
      : `local fallback randomness (drand unreachable — a real deployment delays instead)`);
    ex.seed = sha256(ex.combinedSecret + '|' + beacon.randomness);
    logEvent(ex, 'seed-derived', `seed = sha256(ceremony secret + beacon) = ${ex.seed.slice(0, 24)}… — the paper now exists`);
  }, Math.max(0, t0 - Date.now())));

  return { id, t0, scheduledAt, commitment, bankHash, shareCommitments };
}

// ---------------------------------------------------------------------------
// LIVE CLUSTER — nine real, separate OS processes run a genuine no-dealer
// key ceremony (DKG). The coordinator only relays encrypted fragments between
// them (it cannot read them), collects final-share commitments, and combines
// >=THRESHOLD shares at T-0. Every process streams its own terminal.
// ---------------------------------------------------------------------------
let cluster = null;

function clusterLog(id, line) {
  if (!cluster) return;
  cluster.term.push({ n: cluster.term.length, id, line, t: Date.now() });
}
function coord(line) { clusterLog(0, line); }

function killCluster() {
  if (!cluster) return;
  for (const c of cluster.timers) clearTimeout(c);
  for (const ch of cluster.children) { try { ch.send({ type: 'shutdown' }); } catch {} setTimeout(() => { try { ch.kill(); } catch {} }, 300); }
}

function startCluster(seconds, fast) {
  killCluster();
  const secs = fast ? Math.max(10, Math.min(600, seconds || 15)) : Math.max(MIN_SECONDS, Math.min(600, seconds || 45));
  const scheduledAt = Date.now();
  const id = 'NEET-UG-' + scheduledAt;
  const t0 = scheduledAt + secs * 1000;
  const bankHash = sha256(JSON.stringify(BANK));

  // Two random devices are offline — the 5-of-9 threshold shrugs it off.
  const offline = new Set();
  while (offline.size < 2) offline.add(1 + Math.floor(Math.random() * OFFICIALS.length));
  const onlineIds = OFFICIALS.map((o) => o.id).filter((i) => !offline.has(i));

  const cl = cluster = {
    id, t0, scheduledAt, bankHash, fast, secs,
    children: [], pubs: {}, ready: 0, term: [], timers: [],
    officials: OFFICIALS.map((o) => ({ id: o.id, name: o.name, org: o.org, city: o.city, status: offline.has(o.id) ? 'offline' : 'booting', committed: false })),
    onlineIds, threshold: THRESHOLD, commitments: {}, reveals: {},
    phase: 'booting', seed: null, secret: null, secretHash: null, beacon: null, commitment: null, delivered: {},
  };

  coord(`coordinator up — exam ${id}, unlock in ${secs}s${fast ? ' (fast demo mode)' : ''}`);
  coord(`booting ${OFFICIALS.length} official processes · ${onlineIds.length} online, ${offline.size} offline`);

  // Fork one real process per official (offline ones boot too, then idle).
  OFFICIALS.forEach((o) => {
    const ch = fork(path.join(__dirname, 'official.js'), [String(o.id)], { silent: true });
    cl.children.push(ch);
    ch.stdout.on('data', (d) => String(d).split('\n').forEach((ln) => ln.trim() && clusterLog(o.id, ln.trim())));
    ch.stderr.on('data', (d) => String(d).split('\n').forEach((ln) => ln.trim() && clusterLog(o.id, '! ' + ln.trim())));
    ch.on('message', (m) => onOfficialMessage(cl, o.id, m));
  });

  // T-0: ask online officials to release their final shares.
  cl.timers.push(setTimeout(() => {
    if (cluster !== cl) return;
    coord(`⚡ T-0 — requesting share release from ${onlineIds.length} officials`);
    for (const ch of cl.children) { try { ch.send({ type: 'release' }); } catch {} }
  }, Math.max(0, t0 - Date.now())));

  return { id, t0, scheduledAt, secs, fast, onlineIds };
}

function onOfficialMessage(cl, oid, m) {
  if (cluster !== cl) return;
  if (m.type === 'ready') {
    cl.pubs[oid] = m.pub; cl.ready++;
    const off = cl.officials.find((o) => o.id === oid);
    if (off && off.status === 'booting') off.status = 'waiting';
    if (cl.ready === OFFICIALS.length) {
      cl.phase = 'dkg';
      coord(`all processes ready — broadcasting peer directory, starting DKG`);
      const members = OFFICIALS.map((o) => ({ id: o.id, pub: cl.pubs[o.id] }));
      for (const ch of cl.children) { try { ch.send({ type: 'config', members, onlineIds: cl.onlineIds, threshold: cl.threshold, examId: cl.id }); } catch {} }
    }
  }
  if (m.type === 'relay') {
    // Untrusted bulletin board: forward the ciphertext, cannot read it.
    const target = cl.children[m.to - 1];
    if (target) { try { target.send({ type: 'share', from: m.from, enc: m.enc }); } catch {} }
  }
  if (m.type === 'commitment') {
    cl.commitments[oid] = m.commitment;
    const off = cl.officials.find((o) => o.id === oid);
    if (off) { off.status = 'committed'; off.committed = true; }
    if (Object.keys(cl.commitments).length === cl.onlineIds.length) {
      cl.phase = 'ready';
      // Fairness receipt: bind exam + the final-share fingerprints, before T-0.
      const scs = cl.onlineIds.map((i) => cl.commitments[i]).join(',');
      cl.commitment = sha256(cl.id + '|' + cl.t0 + '|' + cl.scheduledAt + '|' + cl.bankHash + '|' + scs);
      coord(`ceremony complete — key exists in shares only. fairness receipt ${cl.commitment.slice(0, 16)}… published`);
    }
  }
  if (m.type === 'reveal') {
    cl.reveals[oid] = m.share;
    coord(`received final share from #${oid} (${Object.keys(cl.reveals).length}/${cl.threshold} needed)`);
    if (!cl.seed && !cl.finishing && Object.keys(cl.reveals).length >= cl.threshold) {
      cl.finishing = true;
      finishCluster(cl);
    }
  }
}

async function finishCluster(cl) {
  const ids = Object.keys(cl.reveals).map(Number).slice(0, cl.threshold);
  const shares = ids.map((i) => ({ x: i, y: cl.reveals[i] }));
  cl.secret = shamirCombine(shares);
  cl.secretHash = sha256(cl.secret);
  coord(`combined ${cl.threshold} shares → group secret reconstructed (first time it has ever existed)`);
  const beacon = await fetchBeacon(cl.scheduledAt);
  if (cluster !== cl) return;
  cl.beacon = beacon;
  coord(beacon.source === 'drand'
    ? `mixed in drand round ${beacon.round} (produced after the receipt)`
    : `drand unreachable — used local fallback randomness`);
  cl.seed = sha256(cl.secret + '|' + beacon.randomness);
  cl.phase = 'live';
  coord(`seed = sha256(group secret + beacon) = ${cl.seed.slice(0, 16)}… — the paper now exists on every screen`);
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------
function json(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');

  if (url.pathname === '/' || url.pathname === '/index.html' || url.pathname === '/present' || url.pathname === '/source' || url.pathname === '/infographic' || url.pathname === '/cluster') {
    const map = { '/present': 'present.html', '/source': 'source.html', '/infographic': 'infographic.html', '/cluster': 'cluster.html' };
    const file = map[url.pathname] || 'index.html';
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(fs.readFileSync(path.join(__dirname, 'public', file)));
  }

  // Read the source — the whole system, served by the system. Publishing the
  // code is Kerckhoffs's principle in action: security lives in runtime
  // secrets (fragments, beacon, seed), never in the code, so this is safe.
  // Whitelisted filenames only — no arbitrary file access.
  const SOURCE_FILES = {
    'server.js': 'server.js',
    'questionbank.js': 'questionbank.js',
    'public/index.html': 'public/index.html',
    'public/present.html': 'public/present.html',
  };
  if (url.pathname === '/api/source') {
    const name = url.searchParams.get('file');
    if (!name) return json(res, 200, { files: Object.keys(SOURCE_FILES) });
    if (!SOURCE_FILES[name]) return json(res, 403, { error: 'Not a published source file.' });
    const content = fs.readFileSync(path.join(__dirname, SOURCE_FILES[name]), 'utf8');
    return json(res, 200, { name, content, lines: content.split('\n').length });
  }

  // Static images — /img/<name>.(jpg|png) only, no traversal.
  if (url.pathname.startsWith('/img/')) {
    const imgDir = path.join(__dirname, 'public', 'img');
    const resolved = path.normalize(path.join(imgDir, decodeURIComponent(url.pathname.slice(5))));
    const ext = path.extname(resolved).toLowerCase();
    const types = { '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png' };
    if (!resolved.startsWith(imgDir + path.sep) || !types[ext] || !fs.existsSync(resolved)) {
      res.writeHead(404); return res.end('not found');
    }
    res.writeHead(200, { 'Content-Type': types[ext], 'Cache-Control': 'public, max-age=3600' });
    return res.end(fs.readFileSync(resolved));
  }

  if (url.pathname === '/api/schedule' && req.method === 'POST') {
    let body = '';
    req.on('data', c => (body += c));
    req.on('end', () => {
      let secs = 40, fast = false;
      try { const b = JSON.parse(body || '{}'); secs = Number(b.seconds) || 40; fast = !!b.fast; } catch {}
      json(res, 200, scheduleExam(secs, fast));
    });
    return;
  }

  // ---- Live cluster endpoints ----
  if (url.pathname === '/api/cluster/schedule' && req.method === 'POST') {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      let secs = 45, fast = false;
      try { const b = JSON.parse(body || '{}'); secs = Number(b.seconds) || 45; fast = !!b.fast; } catch {}
      json(res, 200, startCluster(secs, fast));
    });
    return;
  }
  if (url.pathname === '/api/cluster/status') {
    if (!cluster) return json(res, 200, { scheduled: false, threshold: THRESHOLD, officials: OFFICIALS.map((o) => ({ ...o, status: 'idle' })) });
    const now = Date.now();
    const base = {
      scheduled: true, id: cluster.id, t0: cluster.t0, now, phase: cluster.phase,
      threshold: cluster.threshold, onlineIds: cluster.onlineIds, commitment: cluster.commitment,
      committed: Object.keys(cluster.commitments).length, revealed: Object.keys(cluster.reveals).length,
      officials: cluster.officials, live: !!cluster.seed,
    };
    if (cluster.seed) base.reveal = { seed: cluster.seed, secret: cluster.secret, secretHash: cluster.secretHash, beacon: cluster.beacon };
    return json(res, 200, base);
  }
  if (url.pathname === '/api/cluster/terminals') {
    const since = Math.max(0, Math.floor(Number(url.searchParams.get('since')) || 0));
    return json(res, 200, { lines: cluster ? cluster.term.slice(since) : [], officials: OFFICIALS });
  }
  if (url.pathname === '/api/cluster/paper') {
    const centerId = url.searchParams.get('center');
    if (!cluster) return json(res, 400, { error: 'No ceremony running.' });
    if (!CENTERS.some((c) => c.id === centerId)) return json(res, 403, { error: 'Unknown center.' });
    if (!cluster.seed) return json(res, 423, { error: 'LOCKED. Paper does not exist yet.' });
    return json(res, 200, { centerId, questions: paperForCenter(cluster.seed, centerId) });
  }

  // The question bank is public — knowing it is just knowing the syllabus.
  if (url.pathname === '/api/bank') {
    return json(res, 200, { bank: BANK, bankHash: sha256(JSON.stringify(BANK)) });
  }

  if (url.pathname === '/api/status') {
    if (!exam) return json(res, 200, { scheduled: false, centers: CENTERS, officials: OFFICIALS.map(o => ({ ...o, status: 'waiting' })), threshold: THRESHOLD, minSeconds: MIN_SECONDS });
    const now = Date.now();
    const live = !!exam.seed;
    const base = {
      scheduled: true, id: exam.id, t0: exam.t0, scheduledAt: exam.scheduledAt, now, live,
      phase: now < exam.t0 ? 'countdown' : (live ? 'live' : 'combining'),
      commitment: exam.commitment, bankHash: exam.bankHash, shareCommitments: exam.shareCommitments,
      threshold: THRESHOLD, centers: CENTERS, minSeconds: MIN_SECONDS,
      officials: exam.officials.map(o => ({ id: o.id, name: o.name, org: o.org, city: o.city, status: o.status, submittedAt: o.submittedAt })),
    };
    if (live) {
      // Commit-reveal: after T-0 everything is public so anyone can re-check.
      base.reveal = {
        seed: exam.seed, secret: exam.combinedSecret, secretHash: exam.secretHash,
        beacon: exam.beacon,
        shares: exam.shares.filter(s => exam.officials.find(o => o.id === s.x)?.status === 'submitted'),
      };
    }
    return json(res, 200, base);
  }

  if (url.pathname === '/api/events') {
    const since = Math.max(0, Math.floor(Number(url.searchParams.get('since')) || 0));
    return json(res, 200, { events: exam ? exam.events.slice(since) : [] });
  }

  if (url.pathname === '/api/paper') {
    const centerId = url.searchParams.get('center');
    if (!exam) return json(res, 400, { error: 'No exam scheduled.' });
    if (!CENTERS.some(c => c.id === centerId)) return json(res, 403, { error: 'Unknown center.' });
    if (!exam.seed) return json(res, 423, { error: 'LOCKED. Paper does not exist yet. Nothing to steal.', t0: exam.t0 });
    if (!exam.delivered[centerId]) {
      exam.delivered[centerId] = true;
      logEvent(exam, 'paper-delivered', `${centerId} — generated locally from seed, watermarked for this center`);
    }
    return json(res, 200, { examId: exam.id, centerId, questions: paperForCenter(exam.seed, centerId) });
  }

  if (url.pathname === '/api/trace' && req.method === 'POST') {
    let body = '';
    req.on('data', c => (body += c));
    req.on('end', () => {
      let text = '';
      try { text = JSON.parse(body || '{}').text || ''; } catch {}
      const centerId = traceWatermark(text);
      const center = CENTERS.find(c => c.id === centerId);
      if (center) logEvent(exam, 'leak-traced', `pasted text fingerprint → ${center.id} (${center.name})`);
      json(res, 200, center ? { traced: true, centerId, centerName: center.name } : { traced: false });
    });
    return;
  }

  res.writeHead(404); res.end('not found');
});

server.listen(PORT, () => console.log(`ZEROLEAK glass-room prototype → http://localhost:${PORT}`));
