const $ = (sel) => document.querySelector(sel);

const EXPIRED_FLAG = 'iam_session_expired';

// Signs the browser out when the idle timeout elapses: ends the server session
// (best effort), remembers why, and reloads so no user data is left on screen.
const sessionGuard = createSessionGuard({
  storageKey: 'iam_user_last_activity',
  keepalive: () => api('/api/users/keepalive', { method: 'POST' }),
  onExpire: async () => {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'timeout' }),
      });
    } catch (e) { /* server session ends on its own anyway */ }
    try { sessionStorage.setItem(EXPIRED_FLAG, '1'); } catch (e) { /* ignore */ }
    location.reload();
  },
});

let currentFeatures = {};
let selectedUser = null;

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && sessionGuard.isRunning() && path !== '/api/auth/login') {
    // The server ended the session (timeout) while the page was open.
    sessionGuard.expire();
    throw new Error('Your session has expired. Please sign in again.');
  }
  if (res.ok) {
    const ttl = Number(res.headers.get('X-Session-Timeout'));
    if (ttl) sessionGuard.setTimeoutSeconds(ttl);
    if (path !== '/api/auth/login') sessionGuard.noteRequest();
  }
  if (!res.ok) {
    const requestId = data.requestId || res.headers.get('X-Request-Id');
    const message = data.error || 'Request failed';
    throw new Error(requestId ? `${message} (ref: ${requestId})` : message);
  }
  return data;
}

async function checkSession() {
  try {
    const me = await api('/api/auth/me');
    showApp(me);
  } catch (e) {
    showLogin();
  }
}

function showLogin() {
  try {
    if (sessionStorage.getItem(EXPIRED_FLAG)) {
      sessionStorage.removeItem(EXPIRED_FLAG);
      $('#loginNotice').textContent = 'You were signed out because your session timed out. Please sign in again.';
      $('#loginNotice').classList.remove('hidden');
    }
  } catch (e) { /* ignore */ }
  $('#loginView').classList.remove('hidden');
  $('#appView').classList.add('hidden');
  $('#userInfo').classList.add('hidden');
}

function showApp(me) {
  currentFeatures = me.features;
  sessionGuard.start(me.sessionTimeoutSeconds);
  $('#loginView').classList.add('hidden');
  $('#appView').classList.remove('hidden');
  $('#userInfo').classList.remove('hidden');
  $('#userLabel').textContent = `${me.username} (${me.domain})`;
  loadActivity(1);
}

const MFA_ERROR_MESSAGES = {
  mfa_failed: 'Multi-factor authentication failed or was cancelled. Please sign in again.',
  mfa_session_expired: 'Your sign-in session expired before multi-factor authentication could complete. Please sign in again.',
};

function showLoginErrorFromQuery() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('error');
  if (code && MFA_ERROR_MESSAGES[code]) {
    $('#loginError').textContent = MFA_ERROR_MESSAGES[code];
    $('#loginError').classList.remove('hidden');
  }
  if (code) {
    // Clean the URL so refreshing doesn't keep re-showing the error.
    params.delete('error');
    const qs = params.toString();
    window.history.replaceState({}, '', window.location.pathname + (qs ? '?' + qs : ''));
  }
}

$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#loginError').classList.add('hidden');
  const username = $('#loginUsername').value.trim();
  const password = $('#loginPassword').value;
  try {
    const data = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
    if (data.mfaRequired && data.redirectUrl) {
      // Full top-level navigation to Duo's hosted prompt - not a fetch.
      window.location.href = data.redirectUrl;
      return;
    }
    showApp(data);
  } catch (err) {
    $('#loginError').textContent = err.message;
    $('#loginError').classList.remove('hidden');
  }
});

$('#logoutBtn').addEventListener('click', async () => {
  sessionGuard.stop();
  await api('/api/auth/logout', { method: 'POST' });
  location.reload();
});

let searchTimeout;
$('#userLookupQuery').addEventListener('input', () => {
  clearTimeout(searchTimeout);
  const q = $('#userLookupQuery').value.trim();
  if (q.length < 2) { $('#searchResults').innerHTML = ''; return; }
  searchTimeout = setTimeout(() => runSearch(q), 300);
});

async function runSearch(q) {
  try {
    const results = await api('/api/users/search?q=' + encodeURIComponent(q));
    renderResults(results);
  } catch (e) {
    $('#searchResults').innerHTML = `<div class="error">${escapeHtml(e.message)}</div>`;
  }
}

function renderResults(results) {
  const container = $('#searchResults');
  if (!results.length) { container.innerHTML = '<div class="muted">No matches</div>'; return; }
  container.innerHTML = '';
  results.forEach((u) => {
    const div = document.createElement('div');
    div.className = 'result-row';
    div.innerHTML = `
      <div>
        <div class="result-name">${escapeHtml(u.displayName || u.cn)}</div>
        <div class="muted">${escapeHtml(u.userPrincipalName || u.sAMAccountName)}</div>
      </div>
      <div class="badges">
        ${u.locked ? '<span class="badge badge-locked">Locked</span>' : ''}
        ${u.disabled ? '<span class="badge badge-disabled">Disabled</span>' : ''}
        ${!u.locked && !u.disabled ? '<span class="badge badge-ok">Active</span>' : ''}
      </div>`;
    div.addEventListener('click', () => selectUser(u));
    container.appendChild(div);
  });
}

function selectUser(u) {
  selectedUser = u;
  $('#selectedUserCard').classList.remove('hidden');
  $('#selUserName').textContent = u.displayName || u.cn;
  const isActive = !u.locked && !u.disabled;
  $('#selUserMeta').innerHTML =
    `${escapeHtml(u.userPrincipalName || u.sAMAccountName)}${u.locked ? ' · Locked' : ''}${u.disabled ? ' · Disabled' : ''}` +
    `${isActive ? ' · <span class="badge badge-ok">Active</span>' : ''}`;
  $('#unlockBtn').classList.toggle('hidden', !currentFeatures.unlock);
  // Nothing to unlock unless the account is actually locked.
  $('#unlockBtn').disabled = !u.locked;
  $('#unlockBtn').title = u.locked ? '' : 'This account is not locked';
  $('#resetBtn').classList.toggle('hidden', !currentFeatures.reset);
  $('#actionMessage').classList.add('hidden');
}

$('#unlockBtn').addEventListener('click', async () => {
  if (!selectedUser || !selectedUser.locked) return;
  const name = selectedUser.displayName || selectedUser.cn;
  try {
    await api(`/api/users/${encodeURIComponent(selectedUser.sAMAccountName)}/unlock`, { method: 'POST' });
    showNotice('Account unlocked', `The account for ${name} has been unlocked.`, false);
    const refreshed = await api(`/api/users/${encodeURIComponent(selectedUser.sAMAccountName)}`);
    selectUser(refreshed);
    if ($('#userLookupQuery').value.trim().length >= 2) runSearch($('#userLookupQuery').value.trim());
  } catch (e) {
    showNotice('Unlock failed', e.message, true);
  } finally {
    loadActivity(1);
  }
});

$('#resetBtn').addEventListener('click', () => {
  $('#resetForUser').textContent = selectedUser.displayName || selectedUser.cn;
  $('#forceChangeRow').classList.toggle('hidden', !currentFeatures.forceChange);
  $('#newPassword').value = '';
  $('#confirmPassword').value = '';
  $('#resetError').classList.add('hidden');
  $('#resetModal').classList.remove('hidden');
});

$('#cancelReset').addEventListener('click', () => $('#resetModal').classList.add('hidden'));

$('#confirmReset').addEventListener('click', async () => {
  const p1 = $('#newPassword').value;
  const p2 = $('#confirmPassword').value;
  if (p1.length < 8) return showResetError('Password must be at least 8 characters');
  if (p1 !== p2) return showResetError('Passwords do not match');
  try {
    await api(`/api/users/${encodeURIComponent(selectedUser.sAMAccountName)}/reset-password`, {
      method: 'POST',
      body: JSON.stringify({ newPassword: p1, forceChange: $('#forceChange').checked }),
    });
    $('#resetModal').classList.add('hidden');
    showNotice('Password reset', `The password for ${selectedUser.displayName || selectedUser.cn} has been reset.`, false);
  } catch (e) {
    showResetError(e.message);
  } finally {
    loadActivity(1);
  }
});

function showResetError(msg) {
  $('#resetError').textContent = msg;
  $('#resetError').classList.remove('hidden');
}

function showNotice(title, text, isError) {
  $('#noticeTitle').textContent = title;
  $('#noticeText').textContent = text;
  const icon = $('#noticeIcon');
  icon.className = 'notice-icon ' + (isError ? 'err' : 'ok');
  icon.innerHTML = isError ? '&#10007;' : '&#10003;';
  $('#noticeModal').classList.remove('hidden');
  $('#noticeOk').focus();
}

$('#noticeOk').addEventListener('click', () => $('#noticeModal').classList.add('hidden'));

function showMessage(msg, isError) {
  const el = $('#actionMessage');
  el.textContent = msg;
  el.className = isError ? 'error' : 'success';
}

// ---------- My activity ----------

const PAGE_SIZES = [25, 50, 100];

// Renders "Showing x-y of n", a rows-per-page selector, and Previous/Next.
function renderPager(container, state, onChange) {
  if (!state.total) { container.innerHTML = ''; return; }
  const start = (state.page - 1) * state.pageSize + 1;
  const end = Math.min(state.total, state.page * state.pageSize);
  container.innerHTML = `
    <span class="muted">Showing ${start}–${end} of ${state.total}</span>
    <span class="pager-controls">
      <label class="pager-size">Rows per page
        <select class="pager-size-select">${PAGE_SIZES.map((n) => `<option value="${n}" ${n === state.pageSize ? 'selected' : ''}>${n}</option>`).join('')}</select>
      </label>
      <button type="button" class="btn-secondary pager-prev" ${state.page <= 1 ? 'disabled' : ''}>Previous</button>
      <span class="muted">Page ${state.page} of ${state.totalPages}</span>
      <button type="button" class="btn-secondary pager-next" ${state.page >= state.totalPages ? 'disabled' : ''}>Next</button>
    </span>`;
  container.querySelector('.pager-size-select').addEventListener('change', (e) => onChange({ page: 1, pageSize: Number(e.target.value) }));
  container.querySelector('.pager-prev').addEventListener('click', () => onChange({ page: state.page - 1, pageSize: state.pageSize }));
  container.querySelector('.pager-next').addEventListener('click', () => onChange({ page: state.page + 1, pageSize: state.pageSize }));
}

const activityState = { page: 1, pageSize: 25 };

// Pass a page number to jump to it; new actions call loadActivity(1) so the
// newest entry (listed first) is visible.
async function loadActivity(page = activityState.page) {
  try {
    const result = await api(`/api/users/audit?page=${page}&pageSize=${activityState.pageSize}`);
    activityState.page = result.page;
    activityState.pageSize = result.pageSize;
    renderActivity(result.rows);
    renderPager($('#activityPager'), result, (next) => {
      activityState.pageSize = next.pageSize;
      loadActivity(next.page);
    });
  } catch (e) {
    $('#activityTable').innerHTML = `<div class="error">${escapeHtml(e.message)}</div>`;
  }
}

function renderActivity(rows) {
  const container = $('#activityTable');
  if (!rows.length) {
    container.innerHTML = '<div class="muted">No activity recorded yet.</div>';
    return;
  }
  container.innerHTML = `<table class="table"><thead><tr>
      <th>Time</th><th>Event</th><th>Target</th><th>Result</th><th>Where</th>
    </tr></thead><tbody>${rows.map(activityRowHtml).join('')}</tbody></table>`;
}

const EVENT_LABELS = {
  login: 'Signed in',
  logout: 'Signed out',
  search: 'Searched',
  unlock: 'Unlocked account',
  reset_password: 'Reset password',
  mfa_challenge: 'MFA challenge sent',
};

function activityRowHtml(r) {
  return `<tr>
    <td>${new Date(r.created_at).toLocaleString()}</td>
    <td>${escapeHtml(EVENT_LABELS[r.event_type] || r.event_type)}</td>
    <td>${escapeHtml(r.target_identifier || '')}</td>
    <td>${r.success ? '<span class="badge badge-ok">Success</span>' : '<span class="badge badge-locked">Failure</span>'}</td>
    <td>${escapeHtml(r.ip_address || '')}</td>
  </tr>`;
}

$('#refreshActivityBtn').addEventListener('click', () => loadActivity());

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : str;
  return div.innerHTML;
}

async function loadVersion() {
  try {
    const v = await api('/api/version');
    $('#appVersion').textContent = v.version;
  } catch (e) {
    $('#appVersion').textContent = 'unknown';
  }
}

loadVersion();
showLoginErrorFromQuery();
checkSession();
