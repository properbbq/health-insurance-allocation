// Shared by the website's pages: signing in, the session, the records, saving, and choosing a
// new password.
//
// The website holds only ciphertext: data/users.json (each sign-in), data/app.enc.json (the app
// itself) and data/records.enc.json (the cost centres and each month's amounts). A password opens
// them here in the browser. The only things that leave the browser are a new password and a save,
// each sealed so only the private repo's Action can open it (tools/hia_core.py), in a GitHub issue
// the person submits themselves.

export const $ = (selector) => document.querySelector(selector);

export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else if (key in node && !key.includes('-')) node[key] = value;
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export class AppError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();
const USERS_URL = 'data/users.json';
const APP_URL = 'data/app.enc.json';
const RECORDS_URL = 'data/records.enc.json';
const PBKDF2_ITERATIONS = 600000;
const MIN_OWN_PASSWORD = 12;
const SESSION_HOURS = 12;
const REMEMBER_DAYS = 30;
// GitHub turns away a page address longer than about 8,000 characters; a save that would make
// one longer is copied, to paste into the issue instead.
const MAX_LINK = 7500;
const KEYS = { session: 'hia.session.v1', username: 'hia.username', local: 'hia.local.v1' };
const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

export const normalizeUsername = (username) => String(username || '').normalize('NFC').trim().toLowerCase();
// Passwords ignore case, spaces and dashes (as in tools/hia_core.py).
export const normalizePassword = (password) => String(password || '').normalize('NFC').toUpperCase().replace(/[\s-]+/g, '');

// ---------------------------------------------------------------- storage

// Storage can be blocked (a private window, say). Then nothing is remembered, and that's all.
const store = {
  get(key, where = 'local') {
    try {
      return JSON.parse((where === 'session' ? sessionStorage : localStorage).getItem(key) || 'null');
    } catch {
      return null;
    }
  },
  set(key, value, where = 'local') {
    try {
      (where === 'session' ? sessionStorage : localStorage).setItem(key, JSON.stringify(value));
      return true;
    } catch {
      return false;
    }
  },
  remove(key, where = 'local') {
    try {
      (where === 'session' ? sessionStorage : localStorage).removeItem(key);
    } catch { /* nothing kept */ }
  },
};

export const lastName = {
  get: () => store.get(KEYS.username) || '',
  set: (name) => store.set(KEYS.username, name),
};

// A session lasts 12 hours, or 30 days with "Keep me signed in". It holds the user key, which
// opens the person's profile until their password changes.
export function saveSession(session) {
  clearSession();
  const hours = session.remember ? REMEMBER_DAYS * 24 : SESSION_HOURS;
  store.set(KEYS.session, { ...session, exp: Date.now() + hours * 3600 * 1000 }, session.remember ? 'local' : 'session');
}

export function loadSession() {
  const session = store.get(KEYS.session, 'session') || store.get(KEYS.session, 'local');
  if (!session?.uk || !(session.exp > Date.now())) {
    if (session) clearSession();
    return null;
  }
  return session;
}

export function clearSession() {
  store.remove(KEYS.session, 'session');
  store.remove(KEYS.session, 'local');
}

// ------------------------------------------------------------------ crypto

const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const b64urlToBytes = (text) => b64ToBytes(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4));

function bytesToB64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}
const bytesToB64url = (bytes) => bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function sha256Hex(text) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8.encode(text)));
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// AES-256-GCM as "<iv>.<ciphertext>" (base64url), with associated data saying what it is and
// whose it is: the same format as seal()/unseal() in tools/hia_core.py.
async function seal(keyBytes, bytes, aad) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8.encode(aad) }, key, bytes));
  return `${bytesToB64url(iv)}.${bytesToB64url(ct)}`;
}

async function unseal(keyBytes, token, aad) {
  const [iv, ct] = String(token).split('.');
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64urlToBytes(iv), additionalData: utf8.encode(aad) }, key, b64urlToBytes(ct)));
}

const sealJSON = (keyBytes, value, aad) => seal(keyBytes, utf8.encode(JSON.stringify(value)), aad);
const unsealJSON = async (keyBytes, token, aad) => JSON.parse(fromUtf8.decode(await unseal(keyBytes, token, aad)));

async function deflate(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function passwordKey(password, saltB64, iterations) {
  const base = await crypto.subtle.importKey('raw', utf8.encode(normalizePassword(password)), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64ToBytes(saltB64), iterations }, base, 256));
}

// A new user key locked with a password: what data/users.json holds for each sign-in.
async function wrapKey(userKey, password, username) {
  const salt = bytesToB64(crypto.getRandomValues(new Uint8Array(16)));
  const key = await seal(await passwordKey(password, salt, PBKDF2_ITERATIONS), userKey, `hia-user-key|${username}`);
  return { salt, iterations: PBKDF2_ITERATIONS, key };
}

// Seal bytes so only the Action can open them: ECDH on P-256 with its request key (from
// data/users.json), then HKDF and AES-GCM. "<prefix>.<one-off public key>.<iv>.<ciphertext>",
// as tools/hia_core.py's open_request expects.
async function sealForAction(requests, bytes, prefix, info, aad) {
  const actionKey = await crypto.subtle.importKey('raw', b64urlToBytes(requests.key), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const oneOff = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: actionKey }, oneOff.privateKey, 256);
  const point = new Uint8Array(await crypto.subtle.exportKey('raw', oneOff.publicKey));
  const hkdf = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const key = new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: point, info: utf8.encode(info) }, hkdf, 256));
  return `${prefix}.${bytesToB64url(point)}.${await seal(key, bytes, aad)}`;
}

// ---------------------------------------------------------------- signing in

async function fetchJSON(url, what) {
  let response;
  try {
    response = await fetch(url, { cache: 'no-cache' });
  } catch {
    throw new AppError('network', 'Couldn’t reach the website. Check your connection and try again.');
  }
  if (response.status === 404) throw new AppError('missing', `The ${what} hasn’t been published yet.`);
  if (!response.ok) throw new AppError('network', `Couldn’t load the ${what} (error ${response.status}).`);
  return response.json();
}

const usersFile = () => fetchJSON(USERS_URL, 'sign-in list');

async function userEntry(username, users) {
  return (users || await usersFile()).users?.[await sha256Hex(`hia-user:${normalizeUsername(username)}`)] || null;
}

export const SIGN_IN_AGAIN = {
  again: 'Please sign in again.',
  changed: 'Your password has changed. Please sign in with the new one.',
};
const signInAgain = (reason = 'again') => Object.assign(new AppError('signin', SIGN_IN_AGAIN[reason]), { reason });
const badLogin = () => new AppError('bad-login', 'That username and password don’t match.');

function checkBrowser() {
  if (!globalThis.crypto?.subtle || typeof CompressionStream === 'undefined') {
    throw new AppError('browser', 'This browser can’t open the website. Please use an up-to-date Chrome, Edge, Safari or Firefox.');
  }
}

export async function signIn(username, password) {
  checkBrowser();
  const name = normalizeUsername(username);
  const entry = await userEntry(name);
  if (!entry?.profile) throw badLogin();
  let userKey;
  try {
    userKey = await unseal(await passwordKey(password, entry.salt, entry.iterations), entry.key, `hia-user-key|${name}`);
  } catch {
    throw badLogin();
  }
  return { username: name, uk: bytesToB64(userKey) };
}

/** The records, decrypted: {records, rev, applied} (applied: the saves they include). */
export async function loadRecords(profile) {
  const blob = await fetchJSON(`${RECORDS_URL}?t=${Date.now()}`, 'records');
  if (blob.epoch !== profile.epoch) return null;
  const records = await unsealJSON(b64ToBytes(profile.dataKey), blob.data, `hia-records|${blob.epoch}`);
  return { records, rev: blob.rev, applied: Array.isArray(blob.applied) ? blob.applied : [] };
}

// Open a signed-in session: the person's profile, the app and the records. Right after a change
// the files can briefly disagree (GitHub Pages updates them one after the other), so this waits a
// little for them to match.
export async function openSession(session) {
  checkBrowser();
  if (!session?.uk) throw signInAgain();
  for (let attempt = 0; ; attempt += 1) {
    const users = await usersFile();
    const entry = await userEntry(session.username, users);
    if (!entry?.profile) throw signInAgain();
    let profile;
    try {
      profile = await unsealJSON(b64ToBytes(session.uk), entry.profile, `hia-profile|${session.username}`);
    } catch {
      throw signInAgain('changed');
    }
    const blob = await fetchJSON(APP_URL, 'app');
    const data = blob.epoch === profile.epoch ? await loadRecords(profile) : null;
    if (blob.epoch === profile.epoch && data) {
      const app = await unsealJSON(b64ToBytes(profile.appKey), blob.data, `hia-app|${blob.epoch}`);
      return { profile, app, data, requests: users.requests || null };
    }
    if (attempt >= 8) throw new AppError('updating', 'The website is being updated. Please try again in a minute.');
    await sleep(4000);
  }
}

// ---------------------------------------------------------------- saving
//
// A save is the records' changes ({people, months, locations, settings}), compressed and sealed
// so only the Action can open it, in a GitHub issue the person submits, signed in to the GitHub
// account linked to their sign-in. The Action applies it to the records in the private data repo
// and republishes the website, and data/records.enc.json then lists the save's id in "applied".

/** The sealed save: "HIAS1.<one-off public key>.<iv>.<ciphertext>" holding {v, u, id, t, base, changes}. */
export async function saveRequest(requests, username, changes, base) {
  checkBrowser();
  const id = bytesToB64url(crypto.getRandomValues(new Uint8Array(12)));
  const body = { v: 1, u: normalizeUsername(username), id, t: Date.now(), base, changes };
  const packed = await deflate(utf8.encode(JSON.stringify(body)));
  const token = await sealForAction(requests, packed, 'HIAS1', 'hia/save', 'hia-save|v1');
  return { id, token };
}

const SAVE_TEXT = 'Changes to the Health Insurance Allocation website’s records, sealed so only the website’s Action can open them. '
  + 'Submit this issue to confirm it’s you: the Action then saves them and closes the issue.';

/**
 * The GitHub page that opens the save's issue, filled in. If the save is too big for a page
 * address, the issue opens asking for it to be pasted, and `block` is what to copy.
 */
export function saveIssueLink(requests, token) {
  const block = `\`\`\`hia\n${token}\n\`\`\`\n`;
  const query = new URLSearchParams({ title: 'Save to the website', body: `<!-- hia:save:v1 -->\n${SAVE_TEXT}\n\n${block}` });
  const link = `https://github.com/${requests.repo}/issues/new?${query}`;
  if (link.length <= MAX_LINK) return { link, fits: true, block };
  const short = new URLSearchParams({
    title: 'Save to the website',
    body: `<!-- hia:save:v1 -->\n${SAVE_TEXT}\n\nPaste the save here (it’s been copied), replacing this line.\n`,
  });
  return { link: `https://github.com/${requests.repo}/issues/new?${short}`, fits: false, block };
}

/**
 * File the save straight away: open its issue with the GitHub API, using the profile's save token
 * (a fine-grained token that can only open issues in the -maker repo). The issue is the same as the
 * one the link fills in, so the Action treats it the same way. Throws if GitHub turns it down.
 */
export async function fileSave(requests, token, saveToken) {
  const body = `<!-- hia:save:v1 -->\n${SAVE_TEXT}\n\n\`\`\`hia\n${token}\n\`\`\`\n`;
  let response;
  try {
    response = await fetch(`https://api.github.com/repos/${requests.repo}/issues`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${saveToken}`, Accept: 'application/vnd.github+json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'Save to the website', body }),
    });
  } catch {
    throw new AppError('network', 'Couldn’t reach GitHub to save.');
  }
  if (!response.ok) throw new AppError('github', `GitHub didn’t take the save (error ${response.status}).`);
  return (await response.json()).number;
}

/**
 * Whether the Action has answered a save's issue yet: null while it's open, or else its reply
 * ("Saved. …" or "Not saved: …"). Errors (no connection, say) count as not answered yet.
 */
export async function saveReply(requests, number, saveToken) {
  const get = async (path) => {
    const response = await fetch(`https://api.github.com/repos/${requests.repo}/issues/${number}${path}`, {
      headers: { Authorization: `Bearer ${saveToken}`, Accept: 'application/vnd.github+json' },
      cache: 'no-store',
    });
    if (!response.ok) throw new AppError('github', `error ${response.status}`);
    return response.json();
  };
  try {
    const issue = await get('');
    if (issue.state !== 'closed') return null;
    const comments = await get('/comments?per_page=100');
    const reply = [...comments].reverse().find((c) => /^(Saved|Not saved)/.test(c.body || ''));
    return reply ? reply.body : null;
  } catch {
    return null;
  }
}

/** Wait until the website's records include the save `id`. Resolves true then, or false after `minutes`. */
export async function waitForSave(id, minutes = 30, stop = () => false) {
  const deadline = Date.now() + minutes * 60 * 1000;
  while (Date.now() < deadline && !stop()) {
    await sleep(5000);
    try {
      const blob = await fetchJSON(`${RECORDS_URL}?t=${Date.now()}`, 'records');
      if (Array.isArray(blob.applied) && blob.applied.includes(id)) return true;
    } catch { /* try again */ }
  }
  return false;
}

// What's kept on this computer between visits (unsaved changes, and saves waiting for GitHub),
// sealed with the records' key so it's as private as the records.
export const kept = {
  async load(profile) {
    const box = store.get(KEYS.local);
    if (!box || box.u !== profile.username || box.epoch !== profile.epoch) return null;
    try {
      return await unsealJSON(b64ToBytes(profile.dataKey), box.data, `hia-local|${profile.username}`);
    } catch {
      return null;
    }
  },
  async save(profile, value) {
    const data = await sealJSON(b64ToBytes(profile.dataKey), value, `hia-local|${profile.username}`);
    return store.set(KEYS.local, { u: profile.username, epoch: profile.epoch, data });
  },
  clear: () => store.remove(KEYS.local),
};

// ------------------------------------------------------------ new passwords
//
// "Forgot your password?" and "Change password" both choose a new password here. The page makes
// a new user key, locks it with the new password, and seals both with the Action's request key,
// so only the Action can open them. The person then submits it as an issue on GitHub, signed in to
// the GitHub account linked to their sign-in: that's what shows it's them. The Action applies it
// and republishes the website, and from then on only the new password works.

// Where new passwords and saves are filed, and the Action's public key (from data/users.json).
export async function requestSettings(users = null) {
  const requests = (users || await usersFile()).requests;
  if (!requests || !/^[\w.-]+\/[\w.-]+$/.test(requests.repo || '') || !/^[A-Za-z0-9_-]{87}$/.test(requests.key || '')) {
    throw new AppError('no-requests', 'Choosing a new password isn’t switched on yet.');
  }
  return requests;
}
export const newPasswordSettings = requestSettings;

// Check a password someone chooses (the same rules as check_own_password in tools/hia_core.py).
export function passwordProblem(password, username) {
  const plain = normalizePassword(password);
  if (plain.length < MIN_OWN_PASSWORD) return `Use at least ${MIN_OWN_PASSWORD} characters. A few words with spaces works well.`;
  if (new Set(plain).size < 5) return 'Use a mix of different characters.';
  const name = normalizeUsername(username).toUpperCase();
  if (plain.includes(name) || plain.includes(name.replace(/\./g, ''))) return 'Don’t include your username.';
  return null;
}

// The sealed request, as tools/hia_core.py's open_request expects it: "HIAN1.<one-off public
// key>.<iv>.<ciphertext>", holding {v, u: username, k: new user key, w: its password lock, t: when}.
export async function newPasswordRequest(requests, username, password) {
  checkBrowser();
  const name = normalizeUsername(username);
  const userKey = crypto.getRandomValues(new Uint8Array(32));
  const wrap = await wrapKey(userKey, password, name);
  const body = utf8.encode(JSON.stringify({ v: 1, u: name, k: bytesToB64(userKey), w: wrap, t: Date.now() }));
  const token = await sealForAction(requests, body, 'HIAN1', 'hia/new-password', 'hia-new-password|v1');
  return { token, salt: wrap.salt, username: name };
}

// The GitHub page that opens the issue, filled in. The issue holds only the sealed request.
export function issueLink(requests, token) {
  const body = '<!-- hia:new-password:v1 -->\n'
    + 'A new password for the Health Insurance Allocation website, sealed so only the website’s Action can open it. '
    + 'Submit this issue to confirm it’s you: the Action then sets the password and closes the issue.\n\n'
    + `\`\`\`hia\n${token}\n\`\`\`\n`;
  const query = new URLSearchParams({ title: 'New password for the website', body });
  return `https://github.com/${requests.repo}/issues/new?${query}`;
}

// Wait for the website to show the new password, by its salt. Resolves true once it does, or
// false after `minutes`.
export async function waitForNewPassword(username, salt, minutes = 15) {
  const deadline = Date.now() + minutes * 60 * 1000;
  while (Date.now() < deadline) {
    await sleep(5000);
    const entry = await userEntry(username).catch(() => null);
    if (entry?.salt === salt) return true;
  }
  return false;
}

// ------------------------------------------------------------- page helpers

// The eye next to a password box shows what's typed only while it's held down (with the mouse,
// a finger, or Space or Enter), and hides it again the moment it's let go.
export function holdToShow(button, inputs) {
  const set = (show) => {
    for (const input of inputs) input.type = show ? 'text' : 'password';
    button.classList.toggle('showing', show);
  };
  const hide = () => set(false);
  button.addEventListener('pointerdown', (event) => {
    if (event.button !== 0) return;
    event.preventDefault(); // keeps the cursor in the password box
    button.setPointerCapture?.(event.pointerId);
    set(true);
  });
  for (const type of ['pointerup', 'pointercancel', 'lostpointercapture', 'blur']) button.addEventListener(type, hide);
  button.addEventListener('keydown', (event) => {
    if (event.key !== ' ' && event.key !== 'Enter') return;
    event.preventDefault();
    if (!event.repeat) set(true);
  });
  button.addEventListener('keyup', (event) => {
    if (event.key === ' ' || event.key === 'Enter') hide();
  });
  button.addEventListener('click', (event) => event.preventDefault());
  button.addEventListener('contextmenu', (event) => event.preventDefault()); // a long press on a phone
  window.addEventListener('blur', hide);
  return hide;
}
