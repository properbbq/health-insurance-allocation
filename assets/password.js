// "Forgot your password?" and "Change password": choose a new password here, then confirm it on
// GitHub by submitting the issue this page fills in (see "new passwords" in common.js).

import {
  $, lastName, loadSession, clearSession, normalizeUsername, normalizePassword, holdToShow, passwordProblem,
  newPasswordSettings, newPasswordRequest, issueLink, waitForNewPassword,
} from './common.js?v=33e18e1deb0e';

const form = $('#password-form');
const userInput = $('#username');
const fresh = $('#new-password');
const again = $('#new-password-again');
const message = $('#message');
const button = $('#submit');
const hides = [holdToShow($('#peek-new'), [fresh]), holdToShow($('#peek-again'), [again])];

// From the app ("Change password"), it's for whoever is signed in.
const session = loadSession();
userInput.value = session?.username || lastName.get();
if (session) $('#back').textContent = 'Back to the website';
if (session) $('#back').href = 'app.html';
(userInput.value ? fresh : userInput).focus();

const switchedOff = () => {
  form.hidden = true;
  $('#off').hidden = false;
};
newPasswordSettings().catch((error) => {
  if (error.code === 'no-requests') switchedOff();
});

function fail(text, field) {
  message.textContent = text;
  message.hidden = false;
  field?.focus();
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (button.disabled) return;
  message.hidden = true;
  hides.forEach((hide) => hide());
  const username = normalizeUsername(userInput.value);
  if (!username) return fail('Enter your username.', userInput);
  if (!/^[a-z0-9][a-z0-9._-]{0,39}$/.test(username)) return fail('Usernames only use letters, numbers and dots.', userInput);
  const problem = passwordProblem(fresh.value, username);
  if (problem) return fail(problem, fresh);
  if (normalizePassword(fresh.value) !== normalizePassword(again.value)) return fail('The two passwords don’t match.', again);
  button.disabled = true;
  button.textContent = 'Preparing…';
  let request;
  let link;
  try {
    const settings = await newPasswordSettings();
    request = await newPasswordRequest(settings, username, fresh.value);
    link = issueLink(settings, request.token);
  } catch (error) {
    if (error.code === 'no-requests') return switchedOff();
    return fail(error.message);
  } finally {
    button.disabled = false;
    button.textContent = 'Continue';
  }
  lastName.set(username);
  form.hidden = true;
  $('#confirm-user').textContent = username;
  $('#github-link').href = link;
  $('#confirm').hidden = false;
  $('#github-link').focus();
  if (await waitForNewPassword(username, request.salt, 30)) {
    clearSession(); // a session from the old password can't open the website any more
    $('#confirm').hidden = true;
    $('#done').hidden = false;
  } else {
    $('#wait').textContent = 'This is taking longer than usual. Look at the issue on GitHub: the website replies there if it couldn’t change the password.';
  }
});
