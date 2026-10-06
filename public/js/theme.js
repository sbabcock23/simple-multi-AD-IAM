// Light / dark theme, shared by the user portal and the admin portal.
//
// Loaded synchronously in <head> so the correct theme is on <html> before
// first paint (no flash). How the choice is remembered:
//
//  * Signed in: stored on the server against that person's account (per
//    portal + username), so it follows them to any browser or device.
//  * Not signed in (login screen): a copy in this browser's localStorage,
//    tagged with whoever it belongs to, so the login page opens in the
//    last-used theme. A person who has never chosen gets the operating
//    system's light/dark setting.
//
// Each portal calls IAMTheme.configure({ endpoint }) once, then
// IAMTheme.onSignIn(me) after login / session restore.
(function () {
  var CACHE_KEY = 'iam_theme';
  var root = document.documentElement;
  var endpoint = null;   // set by configure(); saving only happens when signed in
  var signedInAs = null; // username while signed in

  function isTheme(t) { return t === 'light' || t === 'dark'; }

  function readCache() {
    try {
      var c = JSON.parse(localStorage.getItem(CACHE_KEY) || 'null');
      if (c && isTheme(c.theme)) return c;
    } catch (e) { /* storage unavailable or corrupt */ }
    return null;
  }

  function writeCache(theme, user) {
    try { localStorage.setItem(CACHE_KEY, JSON.stringify({ theme: theme, user: user || null })); } catch (e) { /* ignore */ }
  }

  function systemTheme() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function current() {
    return root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  }

  function updateToggle() {
    var btn = document.getElementById('themeToggle');
    if (!btn) return;
    var dark = current() === 'dark';
    btn.setAttribute('aria-pressed', dark ? 'true' : 'false');
    var label = dark ? 'Switch to light mode' : 'Switch to dark mode';
    btn.setAttribute('aria-label', label);
    btn.title = label;
  }

  function apply(theme) {
    root.setAttribute('data-theme', theme);
    updateToggle();
  }

  // Persists the choice: locally always, and on the server when signed in.
  function save(theme) {
    writeCache(theme, signedInAs);
    if (!signedInAs || !endpoint) return Promise.resolve();
    return fetch(endpoint, {
      method: 'PUT',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ theme: theme }),
    }).catch(function () { /* keeps working from the local copy */ });
  }

  function set(theme) {
    if (!isTheme(theme)) return;
    apply(theme);
    save(theme);
  }

  // Initial theme, before first paint.
  var cached = readCache();
  apply(cached ? cached.theme : systemTheme());

  window.IAMTheme = {
    current: current,
    set: set,
    toggle: function () { set(current() === 'dark' ? 'light' : 'dark'); },
    configure: function (opts) { endpoint = opts && opts.endpoint; },

    // Call once the person is signed in. `me.theme` is their saved server
    // preference (null if they've never picked one).
    onSignIn: function (me) {
      signedInAs = String((me && me.username) || '').toLowerCase() || null;
      if (me && isTheme(me.theme)) {
        apply(me.theme);
        writeCache(me.theme, signedInAs);
        return;
      }
      // Nothing saved yet. Carry over a choice made on the login screen (or
      // by this same person earlier) - but never inherit another person's
      // leftover choice on a shared browser.
      var c = readCache();
      if (c && (c.user === null || c.user === signedInAs)) {
        apply(c.theme);
        save(c.theme);
      } else {
        apply(systemTheme());
      }
    },

    // Call when the session ends. The last theme stays cached for the login screen.
    onSignOut: function () { signedInAs = null; },
  };

  document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('themeToggle');
    if (btn) btn.addEventListener('click', function () { window.IAMTheme.toggle(); });
    updateToggle();
    // Enable colour transitions only after first paint so load doesn't animate.
    requestAnimationFrame(function () { root.classList.add('theme-ready'); });
  });

  // Keep other open tabs of the same portal in step.
  window.addEventListener('storage', function (e) {
    if (e.key !== CACHE_KEY) return;
    var c = readCache();
    if (c) apply(c.theme);
  });

  // People who have never chosen follow the OS if it changes.
  if (window.matchMedia) {
    var mq = window.matchMedia('(prefers-color-scheme: dark)');
    var onChange = function () { if (!readCache()) apply(systemTheme()); };
    if (mq.addEventListener) mq.addEventListener('change', onChange);
  }
})();
