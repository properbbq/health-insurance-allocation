// The sign-in page. The password unlocks the encrypted app in this browser (see common.js).

import { $, signIn, saveSession, loadSession, clearSession, lastName, normalizeUsername, holdToShow, SIGN_IN_AGAIN } from './common.js?v=33e18e1deb0e';

const params = new URLSearchParams(location.search);

if (params.has('signout')) clearSession();
else if (loadSession()) location.replace('app.html');

const form = $('#signin-form');
const userInput = $('#username');
const passwordInput = $('#password');
const message = $('#message');
const button = $('#submit');
userInput.value = lastName.get();
if (Object.hasOwn(SIGN_IN_AGAIN, params.get('why') || '')) showMessage(SIGN_IN_AGAIN[params.get('why')]);
(userInput.value ? passwordInput : userInput).focus();

// Holding the eye down shows what's been typed in the password box; letting go hides it.
const hidePassword = holdToShow($('#peek'), [passwordInput]);

// Going Back to this page restores it as it was left ("Signing in…"): put it back to normal.
window.addEventListener('pageshow', (event) => {
  if (!event.persisted) return;
  button.disabled = false;
  button.textContent = 'Sign in';
  passwordInput.value = '';
  hidePassword();
  message.hidden = true;
});

function showMessage(text, field) {
  message.textContent = text;
  message.hidden = false;
  if (field) field.focus();
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  message.hidden = true;
  const username = normalizeUsername(userInput.value);
  if (!username) return showMessage('Enter your username.', userInput);
  if (!passwordInput.value.trim()) return showMessage('Enter your password.', passwordInput);
  button.disabled = true;
  button.textContent = 'Signing in…';
  try {
    const session = await signIn(username, passwordInput.value);
    lastName.set(session.username);
    hidePassword();
    saveSession({ ...session, remember: $('#remember').checked });
    location.href = 'app.html';
  } catch (error) {
    button.disabled = false;
    button.textContent = 'Sign in';
    showMessage(error.message, error.code === 'bad-login' ? passwordInput : null);
    if (error.code === 'bad-login') passwordInput.select();
  }
});
