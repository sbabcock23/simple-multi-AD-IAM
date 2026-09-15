const $ = (sel) => document.querySelector(sel);

let currentFeatures = {};
let selectedUser = null;

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
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
  $('#loginView').classList.remove('hidden');
  $('#appView').classList.add('hidden');
  $('#userInfo').classList.add('hidden');
}

function showApp(me) {
  currentFeatures = me.features;
  $('#loginView').classList.add('hidden');
  $('#appView').classList.remove('hidden');
  $('#userInfo').classList.remove('hidden');
  $('#userLabel').textContent = `${me.username} (${me.domain})`;
  loadActivity();
}

$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#loginError').classList.add('hidden');
  const username = $('#loginUsername').value.trim();
  const password = $('#loginPassword').value;
  try {
    const data = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
    showApp(data);
  } catch (err) {
    $('#loginError').textContent = err.message;
    $('#loginError').classList.remove('hidden');
  }
});

$('#logoutBtn').addEventListener('click', async () => {
  await api('/api/auth/logout', { method: 'POST' });
  location.reload();
});

let searchTimeout;
$('#searchInput').addEventListener('input', () => {
  clearTimeout(searchTimeout);
  const q = $('#searchInput').value.trim();
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
      </div>`;
    div.addEventListener('click', () => selectUser(u));
    container.appendChild(div);
  });
}

function selectUser(u) {
  selectedUser = u;
  $('#selectedUserCard').classList.remove('hidden');
  $('#selUserName').textContent = u.displayName || u.cn;
  $('#selUserMeta').textContent =
    `${u.userPrincipalName || u.sAMAccountName}${u.locked ? ' · Locked' : ''}${u.disabled ? ' · Disabled' : ''}`;
  $('#unlockBtn').classList.toggle('hidden', !currentFeatures.unlock);
  $('#resetBtn').classList.toggle('hidden', !currentFeatures.reset);
  $('#actionMessage').classList.add('hidden');
}

$('#unlockBtn').addEventListener('click', async () => {
  if (!selectedUser) return;
  try {
    await api(`/api/users/${encodeURIComponent(selectedUser.sAMAccountName)}/unlock`, { method: 'POST' });
    showMessage('Account unlocked successfully.', false);
    const refreshed = await api(`/api/users/${encodeURIComponent(selectedUser.sAMAccountName)}`);
    selectUser(refreshed);
  } catch (e) {
    showMessage(e.message, true);
  } finally {
    loadActivity();
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
    showMessage('Password reset successfully.', false);
  } catch (e) {
    showResetError(e.message);
  } finally {
    loadActivity();
  }
});

function showResetError(msg) {
  $('#resetError').textContent = msg;
  $('#resetError').classList.remove('hidden');
}

function showMessage(msg, isError) {
  const el = $('#actionMessage');
  el.textContent = msg;
  el.className = isError ? 'error' : 'success';
}

// ---------- My activity ----------

async function loadActivity() {
  try {
    const rows = await api('/api/users/audit');
    renderActivity(rows);
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

$('#refreshActivityBtn').addEventListener('click', loadActivity);

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : str;
  return div.innerHTML;
}

checkSession();
