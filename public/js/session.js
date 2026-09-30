// Client-side inactivity timer shared by the user portal and the admin
// portal. Each page creates its own guard with its own storage key, so the
// two portals' timeouts are fully independent. The server enforces the same
// timeout on the session cookie (sliding, refreshed on every authenticated
// request); this guard makes the browser sign out on its own the moment the
// session ends, instead of waiting for the next click to fail.
function createSessionGuard({ storageKey, keepalive, onExpire }) {
  const EVENTS = ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart', 'click'];
  const CHECK_MS = 5000;
  let timeoutMs = 0;
  let running = false;
  let lastActivity = 0;
  let lastTouch = 0;
  let interval = null;

  function readShared() {
    try { return Number(localStorage.getItem(storageKey)) || 0; } catch (e) { return 0; }
  }
  function writeShared(t) {
    try { localStorage.setItem(storageKey, String(t)); } catch (e) { /* storage unavailable */ }
  }

  // Counts as activity in this tab and, via localStorage, in any other tab
  // of the same portal (they share one session cookie).
  function markActive(now) {
    lastActivity = now;
    writeShared(now);
  }

  function onActivity() {
    if (!running) return;
    const now = Date.now();
    if (now - lastActivity < 1000) return;
    markActive(now);
    // Keep the server-side session alive while the person is actively using
    // the page, even if they aren't making API calls (e.g. typing a password).
    if (now - lastTouch >= Math.min(60000, timeoutMs / 4)) {
      lastTouch = now;
      Promise.resolve(keepalive()).catch(() => {});
    }
  }

  function check() {
    if (!running) return;
    const last = Math.max(lastActivity, readShared());
    if (Date.now() - last >= timeoutMs) expire();
  }

  function expire() {
    if (!running) return;
    stop();
    onExpire();
  }

  function start(timeoutSeconds) {
    if (timeoutSeconds) timeoutMs = timeoutSeconds * 1000;
    if (!timeoutMs) timeoutMs = 30 * 60 * 1000;
    if (running) return;
    running = true;
    const now = Date.now();
    lastTouch = now;
    markActive(now);
    EVENTS.forEach((ev) => window.addEventListener(ev, onActivity, { passive: true }));
    document.addEventListener('visibilitychange', check);
    interval = setInterval(check, CHECK_MS);
  }

  function stop() {
    running = false;
    if (interval) clearInterval(interval);
    interval = null;
    EVENTS.forEach((ev) => window.removeEventListener(ev, onActivity));
    document.removeEventListener('visibilitychange', check);
  }

  return {
    start,
    stop,
    expire,
    isRunning: () => running,
    setTimeoutSeconds(seconds) { if (seconds > 0) timeoutMs = seconds * 1000; },
    // An authenticated API call just succeeded, so the server has refreshed the session.
    noteRequest() {
      if (!running) return;
      const now = Date.now();
      lastTouch = now;
      markActive(now);
    },
  };
}
