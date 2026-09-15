const $ = (sel) => document.querySelector(sel);

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
    const me = await api('/api/admin/me');
    showApp(me);
  } catch (e) {
    showLogin();
  }
}

function showLogin() {
  $('#adminLoginView').classList.remove('hidden');
  $('#adminAppView').classList.add('hidden');
  $('#adminInfo').classList.add('hidden');
}

function showApp(me) {
  $('#adminLoginView').classList.add('hidden');
  $('#adminAppView').classList.remove('hidden');
  $('#adminInfo').classList.remove('hidden');
  $('#adminLabel').textContent = me.username;
  loadDomains();
  loadAdmins();
  loadSettings();
  loadAuditLog();
}

$('#adminLoginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#adminLoginError').classList.add('hidden');
  try {
    const data = await api('/api/admin/login', {
      method: 'POST',
      body: JSON.stringify({ username: $('#adminUsername').value.trim(), password: $('#adminPassword').value }),
    });
    showApp(data);
  } catch (err) {
    $('#adminLoginError').textContent = err.message;
    $('#adminLoginError').classList.remove('hidden');
  }
});

$('#adminLogoutBtn').addEventListener('click', async () => {
  await api('/api/admin/logout', { method: 'POST' });
  location.reload();
});

// ---------- Domains ----------

let domainsCache = [];

async function loadDomains() {
  domainsCache = await api('/api/admin/domains');
  renderDomainsTable();
  renderAuditDomainOptions();
}

function renderDomainsTable() {
  const container = $('#domainsTable');
  if (!domainsCache.length) {
    container.innerHTML = '<div class="muted">No domains configured yet.</div>';
    return;
  }
  container.innerHTML = `<table class="table"><thead><tr>
      <th>Name</th><th>Suffix</th><th>LDAP servers</th><th>Features</th><th>Audit</th><th>Status</th><th></th>
    </tr></thead><tbody>${domainsCache.map(rowHtml).join('')}</tbody></table>`;

  domainsCache.forEach((d) => {
    $(`#edit-${d.id}`).addEventListener('click', () => openDomainModal(d));
    $(`#del-${d.id}`).addEventListener('click', () => deleteDomain(d.id));
  });
}

function rowHtml(d) {
  const feats = [
    d.feature_unlock ? 'Unlock' : null,
    d.feature_reset ? 'Reset' : null,
    d.feature_force_change ? 'Force change' : null,
  ].filter(Boolean).join(', ') || 'None';
  return `<tr>
    <td>${escapeHtml(d.name)}</td>
    <td>${escapeHtml(d.domain_suffix)}</td>
    <td>${d.ldap_urls.map(escapeHtml).join('<br/>')}</td>
    <td>${feats}</td>
    <td>${d.audit_enabled ? '<span class="badge badge-ok">On</span>' : '<span class="badge badge-disabled">Off</span>'}</td>
    <td>${d.enabled ? '<span class="badge badge-ok">Enabled</span>' : '<span class="badge badge-disabled">Disabled</span>'}</td>
    <td><button id="edit-${d.id}" class="btn-link">Edit</button> <button id="del-${d.id}" class="btn-link danger">Delete</button></td>
  </tr>`;
}

$('#newDomainBtn').addEventListener('click', () => openDomainModal(null));

function openDomainModal(d) {
  $('#domainError').classList.add('hidden');
  $('#domainTestResult').classList.add('hidden');
  $('#domainModalTitle').textContent = d ? 'Edit domain' : 'Add domain';
  $('#domainId').value = d ? d.id : '';
  $('#dName').value = d ? d.name : '';
  $('#dSuffix').value = d ? d.domain_suffix : '';
  $('#dBaseDn').value = d ? d.base_dn : '';
  $('#dTls').checked = d ? !!d.tls_reject_unauthorized : true;
  $('#dEnabled').checked = d ? !!d.enabled : true;
  $('#dAuditEnabled').checked = d ? !!d.audit_enabled : true;
  $('#dFeatUnlock').checked = d ? !!d.feature_unlock : true;
  $('#dFeatReset').checked = d ? !!d.feature_reset : true;
  $('#dFeatForce').checked = d ? !!d.feature_force_change : true;

  const servers = d && d.ldap_urls && d.ldap_urls.length ? d.ldap_urls : [''];
  renderServerRows(servers);

  $('#domainModal').classList.remove('hidden');
}

function renderServerRows(servers) {
  const list = $('#dServersList');
  list.innerHTML = '';
  servers.forEach((val) => addServerRow(val));
}

function addServerRow(value = '') {
  const row = document.createElement('div');
  row.style.display = 'flex';
  row.style.gap = '8px';
  row.style.alignItems = 'center';
  row.innerHTML = `
    <input type="text" class="server-url" placeholder="ldaps://dc1.contoso.com:636" style="flex:1; margin-top:6px;" value="${escapeAttr(value)}"/>
    <button type="button" class="btn-link danger remove-server">Remove</button>
  `;
  row.querySelector('.remove-server').addEventListener('click', () => {
    if ($('#dServersList').children.length > 1) row.remove();
  });
  $('#dServersList').appendChild(row);
}

$('#addServerBtn').addEventListener('click', () => addServerRow(''));

$('#cancelDomain').addEventListener('click', () => $('#domainModal').classList.add('hidden'));

function collectServerUrls() {
  return Array.from(document.querySelectorAll('.server-url')).map((i) => i.value.trim()).filter(Boolean);
}

function domainPayload() {
  return {
    name: $('#dName').value.trim(),
    domain_suffix: $('#dSuffix').value.trim().toLowerCase(),
    base_dn: $('#dBaseDn').value.trim(),
    ldap_urls: collectServerUrls(),
    tls_reject_unauthorized: $('#dTls').checked,
    enabled: $('#dEnabled').checked,
    audit_enabled: $('#dAuditEnabled').checked,
    feature_unlock: $('#dFeatUnlock').checked,
    feature_reset: $('#dFeatReset').checked,
    feature_force_change: $('#dFeatForce').checked,
  };
}

$('#testDomainBtn').addEventListener('click', async () => {
  const urls = collectServerUrls();
  const resultEl = $('#domainTestResult');
  resultEl.classList.remove('hidden');
  resultEl.textContent = 'Testing...';
  try {
    const { results } = await api('/api/admin/test-connection', {
      method: 'POST',
      body: JSON.stringify({ ldap_urls: urls, tls_reject_unauthorized: $('#dTls').checked }),
    });
    resultEl.innerHTML = results.map((r) =>
      `${r.ok ? '✅' : '❌'} ${escapeHtml(r.url)}${r.ok ? '' : ' — ' + escapeHtml(r.error)}`
    ).join('<br/>');
  } catch (e) {
    resultEl.textContent = 'Test failed: ' + e.message;
  }
});

$('#saveDomain').addEventListener('click', async () => {
  const id = $('#domainId').value;
  const payload = domainPayload();
  if (!payload.name || !payload.domain_suffix || !payload.base_dn || !payload.ldap_urls.length) {
    return domainError('Please fill in all required fields, including at least one LDAP server.');
  }
  try {
    if (id) await api(`/api/admin/domains/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
    else await api('/api/admin/domains', { method: 'POST', body: JSON.stringify(payload) });
    $('#domainModal').classList.add('hidden');
    loadDomains();
  } catch (e) {
    domainError(e.message);
  }
});

function domainError(msg) {
  $('#domainError').textContent = msg;
  $('#domainError').classList.remove('hidden');
}

async function deleteDomain(id) {
  if (!confirm('Delete this domain? This cannot be undone.')) return;
  await api(`/api/admin/domains/${id}`, { method: 'DELETE' });
  loadDomains();
}

// ---------- Settings ----------

async function loadSettings() {
  const s = await api('/api/admin/settings');
  $('#globalAuditEnabled').checked = !!s.auditLoggingEnabled;
}

$('#saveSettingsBtn').addEventListener('click', async () => {
  await api('/api/admin/settings', {
    method: 'PUT',
    body: JSON.stringify({ auditLoggingEnabled: $('#globalAuditEnabled').checked }),
  });
  $('#settingsSaved').classList.remove('hidden');
  setTimeout(() => $('#settingsSaved').classList.add('hidden'), 2000);
});

// ---------- Audit log ----------

function renderAuditDomainOptions() {
  const select = $('#auditDomainFilter');
  const current = select.value;
  select.innerHTML = '<option value="">All domains</option><option value="unmatched">Unmatched domain attempts</option>' +
    domainsCache.map((d) => `<option value="${d.id}">${escapeHtml(d.name)} (${escapeHtml(d.domain_suffix)})</option>`).join('');
  select.value = current;
}

function auditQueryParams() {
  const params = new URLSearchParams();
  const domainId = $('#auditDomainFilter').value;
  const eventType = $('#auditEventFilter').value;
  const success = $('#auditResultFilter').value;
  if (domainId) params.set('domainId', domainId);
  if (eventType) params.set('eventType', eventType);
  if (success !== '') params.set('success', success);
  return params;
}

async function loadAuditLog() {
  const params = auditQueryParams();
  const rows = await api('/api/admin/audit?' + params.toString());
  renderAuditTable(rows);
}

function renderAuditTable(rows) {
  const container = $('#auditTable');
  if (!rows.length) {
    container.innerHTML = '<div class="muted">No matching audit entries.</div>';
    return;
  }
  container.innerHTML = `<table class="table"><thead><tr>
      <th>Time</th><th>Domain</th><th>Event</th><th>Actor</th><th>Target</th><th>Result</th><th>IP</th><th>Detail</th>
    </tr></thead><tbody>${rows.map(auditRowHtml).join('')}</tbody></table>`;
}

function auditRowHtml(r) {
  return `<tr>
    <td>${new Date(r.created_at).toLocaleString()}</td>
    <td>${escapeHtml(r.domain_label || '—')}</td>
    <td>${escapeHtml(r.event_type)}</td>
    <td>${escapeHtml(r.actor_username)}</td>
    <td>${escapeHtml(r.target_identifier || '')}</td>
    <td>${r.success ? '<span class="badge badge-ok">Success</span>' : '<span class="badge badge-locked">Failure</span>'}</td>
    <td>${escapeHtml(r.ip_address || '')}</td>
    <td>${escapeHtml(r.detail || '')}</td>
  </tr>`;
}

$('#refreshAuditBtn').addEventListener('click', loadAuditLog);
$('#auditDomainFilter').addEventListener('change', loadAuditLog);
$('#auditEventFilter').addEventListener('change', loadAuditLog);
$('#auditResultFilter').addEventListener('change', loadAuditLog);

$('#downloadAuditBtn').addEventListener('click', () => {
  const params = auditQueryParams();
  window.location.href = '/api/admin/audit/export?' + params.toString();
});

// ---------- Admin users ----------

async function loadAdmins() {
  const admins = await api('/api/admin/admins');
  const container = $('#adminsTable');
  container.innerHTML = `<table class="table"><thead><tr><th>Username</th><th>Created</th><th></th></tr></thead>
    <tbody>${admins.map(a => `<tr>
      <td>${escapeHtml(a.username)}</td>
      <td>${new Date(a.created_at).toLocaleString()}</td>
      <td><button class="btn-link danger" data-del="${a.id}">Delete</button></td>
    </tr>`).join('')}</tbody></table>`;
  container.querySelectorAll('[data-del]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!confirm('Delete this admin user?')) return;
      try {
        await api(`/api/admin/admins/${btn.dataset.del}`, { method: 'DELETE' });
        loadAdmins();
      } catch (e) {
        alert(e.message);
      }
    });
  });
}

$('#newAdminBtn').addEventListener('click', () => {
  $('#adminModalError').classList.add('hidden');
  $('#newAdminUsername').value = '';
  $('#newAdminPassword').value = '';
  $('#adminModal').classList.remove('hidden');
});
$('#cancelAdmin').addEventListener('click', () => $('#adminModal').classList.add('hidden'));
$('#saveAdmin').addEventListener('click', async () => {
  try {
    await api('/api/admin/admins', {
      method: 'POST',
      body: JSON.stringify({ username: $('#newAdminUsername').value.trim(), password: $('#newAdminPassword').value }),
    });
    $('#adminModal').classList.add('hidden');
    loadAdmins();
  } catch (e) {
    $('#adminModalError').textContent = e.message;
    $('#adminModalError').classList.remove('hidden');
  }
});

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : str;
  return div.innerHTML;
}

function escapeAttr(str) {
  return escapeHtml(str).replace(/"/g, '&quot;');
}

checkSession();
