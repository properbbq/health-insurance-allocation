// The app page: opens the encrypted app and records with the signed-in session and runs the app
// here. The app finds what it needs in globalThis.hiaHost: the workbook template, the records,
// and the ways to save, check a save has been applied, and keep unsaved changes on this computer.
// "Change password" is password.html.

import {
  $, el, loadSession, clearSession, openSession, loadRecords, requestSettings, saveRequest, saveIssueLink, fileSave, saveReply, waitForSave, kept,
} from './common.js?v=33e18e1deb0e';

const session = loadSession();

function notice(tone, ...content) {
  const box = el('div', { class: `notice notice-${tone}` }, el('div', { class: 'notice-text' }, ...content));
  $('#notices').append(box);
  return box;
}

// The app's page, built from the tree tools/hia_build.py made of site/index.html (so it needs
// no innerHTML).
const SVG = 'http://www.w3.org/2000/svg';
function build(node, inSvg = false) {
  if (typeof node === 'string') return document.createTextNode(node);
  const [tag, attributes, ...children] = node;
  const svg = inSvg || tag === 'svg';
  const element = svg ? document.createElementNS(SVG, tag) : document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) element.setAttribute(name, value);
  for (const child of children) element.append(build(child, svg));
  return element;
}

// The app's modules, each from a blob: address, with every import pointed at the module it names.
async function runModules(modules, entry) {
  const urls = new Map();
  const loading = new Set();
  const load = (name) => {
    if (urls.has(name)) return urls.get(name);
    if (loading.has(name) || !Object.hasOwn(modules, name)) throw new Error(`the app is incomplete (${name})`);
    loading.add(name);
    const code = modules[name].replace(/from '\.\/([\w-]+\.js)'/g, (match, dependency) => `from '${load(dependency)}'`);
    const url = URL.createObjectURL(new Blob([code], { type: 'text/javascript' }));
    urls.set(name, url);
    return url;
  };
  await import(load(entry));
}

async function start() {
  let opened;
  try {
    opened = await openSession(session);
  } catch (error) {
    if (error.code === 'signin') {
      clearSession();
      location.replace(`index.html?why=${error.reason || 'again'}`);
      return;
    }
    $('#app').replaceChildren(el('div', { class: 'page' }, el('div', { class: 'notice notice-error' },
      el('div', { class: 'notice-text' }, error.message),
      el('button', { class: 'btn btn-sm', type: 'button', onclick: () => location.reload() }, 'Try again'))));
    return;
  }
  const { profile, app, data } = opened;
  $('#user-name').textContent = profile.name;
  $('#user').hidden = false;
  if (profile.first) {
    notice('warn', el('strong', {}, 'Choose your own password. '),
      'You’re still using the one you were given, which others could guess. ',
      el('a', { class: 'btn btn-sm btn-primary', href: 'password.html' }, 'Change password'));
  }
  globalThis.hiaHost = {
    template: app.template,
    profile: { username: profile.username, name: profile.name },
    data,
    // The records as they are on the website now.
    refresh: async () => (await loadRecords(profile)) || data,
    // Seal changes for the Action and file them straight away. Only without a save token (or if
    // GitHub turns it down) does it fall back to a link, to submit the issue on GitHub by hand.
    async save(changes, base) {
      const requests = await requestSettings();
      const { id, token } = await saveRequest(requests, profile.username, changes, base);
      const link = saveIssueLink(requests, token);
      if (profile.saveToken) {
        try {
          const issue = await fileSave(requests, token, profile.saveToken);
          return { id, ...link, submitted: true, issue };
        } catch (error) {
          return { id, ...link, submitted: false, problem: error.message };
        }
      }
      return { id, ...link, submitted: false };
    },
    // The Action's reply on a save's issue, once it has answered (null until then).
    async checkSave(issue) {
      if (!profile.saveToken || !issue) return null;
      return saveReply(await requestSettings(), issue, profile.saveToken);
    },
    waitForSave,
    kept: {
      load: () => kept.load(profile),
      save: (value) => kept.save(profile, value),
      clear: () => kept.clear(),
    },
  };
  $('#app').replaceChildren(build(app.markup));
  try {
    await runModules(app.modules, app.entry);
  } catch (error) {
    notice('error', `The app couldn’t start (${error.message}). Try reloading the page.`);
  }
}

if (!session) location.replace('index.html');
else start();
