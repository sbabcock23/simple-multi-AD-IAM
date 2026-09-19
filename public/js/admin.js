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

function splitList(str) {
  return String(str || '').split(',').map((s) => s.trim()).filter(Boolean);
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
  loadTemplates();
  initReportTabs();
  loadReports();
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
  container.innerHTML = `<div class="table-wrap"><table class="table"><thead><tr>
      <th>Name</th><th>Suffix</th><th>LDAP servers</th><th>Allowed groups</th><th>Features</th><th>Audit</th><th>Alerts</th><th>Status</th><th></th>
    </tr></thead><tbody>${domainsCache.map(rowHtml).join('')}</tbody></table></div>`;

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
    <td>${d.allowed_groups.map(escapeHtml).join(', ')}</td>
    <td>${feats}</td>
    <td>${d.audit_enabled ? '<span class="badge badge-ok">On</span>' : '<span class="badge badge-disabled">Off</span>'}</td>
    <td>${d.alert_config.enabled ? '<span class="badge badge-ok">On</span>' : '<span class="badge badge-disabled">Off</span>'}</td>
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

  $('#dNetbiosName').value = d ? (d.netbios_name || '') : '';
  $('#dLookupDn').value = d ? (d.lookup_bind_dn || '') : '';
  $('#dLookupPassword').value = '';
  $('#dLookupPassword').placeholder = d && d.has_lookup_password ? 'Leave blank to keep existing' : 'No password set';
  $('#dLookupTestEmail').value = '';
  $('#lookupTestResult').classList.add('hidden');

  const alertCfg = d ? d.alert_config : { enabled: true, onLoginFailure: true, onAccountAction: true, recipients: [], smtpOverride: false, smtp: {} };
  $('#dAlertsEnabled').checked = !!alertCfg.enabled;
  $('#dAlertLoginFailure').checked = alertCfg.onLoginFailure !== false;
  $('#dAlertAccountAction').checked = alertCfg.onAccountAction !== false;
  $('#dAlertRecipients').value = (alertCfg.recipients || []).join(', ');
  $('#dSmtpOverride').checked = !!alertCfg.smtpOverride;
  $('#dSmtpHost').value = (alertCfg.smtp && alertCfg.smtp.host) || '';
  $('#dSmtpPort').value = (alertCfg.smtp && alertCfg.smtp.port) || '';
  $('#dSmtpFrom').value = (alertCfg.smtp && alertCfg.smtp.from) || '';
  $('#dSmtpUsername').value = (alertCfg.smtp && alertCfg.smtp.username) || '';
  $('#dSmtpSecure').checked = !!(alertCfg.smtp && alertCfg.smtp.secure);
  $('#dSmtpTlsVerify').checked = alertCfg.smtp ? alertCfg.smtp.tlsRejectUnauthorized !== false : true;
  $('#dSmtpPassword').value = '';
  $('#dSmtpPassword').placeholder = (alertCfg.smtp && alertCfg.smtp.hasPassword) ? 'Leave blank to keep existing' : 'No password set';

  const servers = d && d.ldap_urls && d.ldap_urls.length ? d.ldap_urls : [''];
  renderListRows('#dServersList', servers, 'server-url', 'ldaps://dc1.contoso.com:636');

  const groups = d && d.allowed_groups && d.allowed_groups.length ? d.allowed_groups : ['Domain Admins'];
  renderListRows('#dGroupsList', groups, 'group-name', 'Group name, e.g. Help Desk');

  $('#domainModal').classList.remove('hidden');
}

function renderListRows(containerSel, values, cssClass, placeholder) {
  const list = $(containerSel);
  list.innerHTML = '';
  values.forEach((val) => addListRow(containerSel, cssClass, placeholder, val));
}

function addListRow(containerSel, cssClass, placeholder, value = '') {
  const row = document.createElement('div');
  row.style.display = 'flex';
  row.style.gap = '8px';
  row.style.alignItems = 'center';
  row.innerHTML = `
    <input type="text" class="${cssClass}" placeholder="${escapeAttr(placeholder)}" style="flex:1; margin-top:6px;" value="${escapeAttr(value)}"/>
    <button type="button" class="btn-link danger remove-row">Remove</button>
  `;
  row.querySelector('.remove-row').addEventListener('click', () => {
    if ($(containerSel).children.length > 1) row.remove();
  });
  $(containerSel).appendChild(row);
}

$('#addServerBtn').addEventListener('click', () => addListRow('#dServersList', 'server-url', 'ldaps://dc1.contoso.com:636', ''));
$('#addGroupBtn').addEventListener('click', () => addListRow('#dGroupsList', 'group-name', 'Group name, e.g. Help Desk', ''));

$('#cancelDomain').addEventListener('click', () => $('#domainModal').classList.add('hidden'));

function collectValues(containerSel, cssClass) {
  return Array.from(document.querySelectorAll(`${containerSel} .${cssClass}`)).map((i) => i.value.trim()).filter(Boolean);
}

function domainAlertConfigPayload() {
  return {
    enabled: $('#dAlertsEnabled').checked,
    onLoginFailure: $('#dAlertLoginFailure').checked,
    onAccountAction: $('#dAlertAccountAction').checked,
    recipients: splitList($('#dAlertRecipients').value),
    smtpOverride: $('#dSmtpOverride').checked,
    smtp: {
      host: $('#dSmtpHost').value.trim(),
      port: $('#dSmtpPort').value.trim(),
      secure: $('#dSmtpSecure').checked,
      tlsRejectUnauthorized: $('#dSmtpTlsVerify').checked,
      username: $('#dSmtpUsername').value.trim(),
      from: $('#dSmtpFrom').value.trim(),
      password: $('#dSmtpPassword').value,
    },
  };
}

function domainPayload() {
  return {
    name: $('#dName').value.trim(),
    domain_suffix: $('#dSuffix').value.trim().toLowerCase(),
    base_dn: $('#dBaseDn').value.trim(),
    ldap_urls: collectValues('#dServersList', 'server-url'),
    netbios_name: $('#dNetbiosName').value.trim(),
    lookup_bind_dn: $('#dLookupDn').value.trim(),
    lookup_bind_password: $('#dLookupPassword').value,
    tls_reject_unauthorized: $('#dTls').checked,
    enabled: $('#dEnabled').checked,
    audit_enabled: $('#dAuditEnabled').checked,
    feature_unlock: $('#dFeatUnlock').checked,
    feature_reset: $('#dFeatReset').checked,
    feature_force_change: $('#dFeatForce').checked,
    allowed_groups: collectValues('#dGroupsList', 'group-name'),
    alert_config: domainAlertConfigPayload(),
  };
}

$('#testDomainBtn').addEventListener('click', async () => {
  const urls = collectValues('#dServersList', 'server-url');
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

$('#testDomainEmailBtn').addEventListener('click', async () => {
  const id = $('#domainId').value;
  const resultEl = $('#domainTestResult');
  resultEl.classList.remove('hidden');
  resultEl.textContent = 'Sending...';
  try {
    let body;
    if (id) {
      // Saved domain: test its effective (saved + resolved) configuration.
      body = { domainId: id };
    } else {
      // Not saved yet: test using whatever is currently typed in the form.
      const cfg = domainAlertConfigPayload();
      body = { smtp: cfg.smtp, recipients: cfg.recipients.length ? cfg.recipients : undefined };
    }
    const result = await api('/api/admin/alerts/test', { method: 'POST', body: JSON.stringify(body) });
    resultEl.textContent = `✅ Test email sent to: ${result.recipients.join(', ')}`;
  } catch (e) {
    resultEl.textContent = '❌ ' + e.message;
  }
});

$('#testLookupBtn').addEventListener('click', async () => {
  const resultEl = $('#lookupTestResult');
  resultEl.classList.remove('hidden');
  resultEl.textContent = 'Testing...';
  const id = $('#domainId').value;
  const testEmail = $('#dLookupTestEmail').value.trim();
  const lookupDn = $('#dLookupDn').value.trim();
  const lookupPassword = $('#dLookupPassword').value;

  const body = id
    ? { domainId: id, lookup_bind_dn: lookupDn || undefined, lookup_bind_password: lookupPassword || undefined, testEmail }
    : {
        ldap_urls: collectValues('#dServersList', 'server-url'),
        base_dn: $('#dBaseDn').value.trim(),
        tls_reject_unauthorized: $('#dTls').checked,
        lookup_bind_dn: lookupDn,
        lookup_bind_password: lookupPassword,
        testEmail,
      };

  try {
    const result = await api('/api/admin/test-lookup', { method: 'POST', body: JSON.stringify(body) });
    resultEl.textContent = '✅ ' + result.message;
  } catch (e) {
    resultEl.textContent = '❌ ' + e.message;
  }
});

$('#saveDomain').addEventListener('click', async () => {
  const id = $('#domainId').value;
  const payload = domainPayload();
  if (!payload.name || !payload.domain_suffix || !payload.base_dn || !payload.ldap_urls.length) {
    return domainError('Please fill in all required fields, including at least one LDAP server.');
  }
  if (!payload.allowed_groups.length) {
    return domainError('At least one allowed login group is required (defaults to Domain Admins).');
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

// ---------- Global settings ----------

async function loadSettings() {
  const [s, alerts] = await Promise.all([
    api('/api/admin/settings'),
    api('/api/admin/alerts'),
  ]);
  $('#globalAuditEnabled').checked = !!s.auditLoggingEnabled;

  $('#globalAlertsEnabled').checked = !!alerts.enabled;
  $('#gAlertLoginFailure').checked = alerts.onLoginFailure !== false;
  $('#gAlertAccountAction').checked = alerts.onAccountAction !== false;
  $('#gAlertRecipients').value = (alerts.recipients || []).join(', ');
  $('#gSmtpHost').value = (alerts.smtp && alerts.smtp.host) || '';
  $('#gSmtpPort').value = (alerts.smtp && alerts.smtp.port) || '';
  $('#gSmtpFrom').value = (alerts.smtp && alerts.smtp.from) || '';
  $('#gSmtpUsername').value = (alerts.smtp && alerts.smtp.username) || '';
  $('#gSmtpSecure').checked = !!(alerts.smtp && alerts.smtp.secure);
  $('#gSmtpTlsVerify').checked = alerts.smtp ? alerts.smtp.tlsRejectUnauthorized !== false : true;
  $('#gSmtpPassword').value = '';
  $('#gSmtpPassword').placeholder = (alerts.smtp && alerts.smtp.hasPassword) ? 'Leave blank to keep existing' : 'Not set';
}

$('#saveSettingsBtn').addEventListener('click', async () => {
  await api('/api/admin/settings', {
    method: 'PUT',
    body: JSON.stringify({ auditLoggingEnabled: $('#globalAuditEnabled').checked }),
  });
  await api('/api/admin/alerts', {
    method: 'PUT',
    body: JSON.stringify({
      enabled: $('#globalAlertsEnabled').checked,
      onLoginFailure: $('#gAlertLoginFailure').checked,
      onAccountAction: $('#gAlertAccountAction').checked,
      recipients: splitList($('#gAlertRecipients').value),
      smtp: {
        host: $('#gSmtpHost').value.trim(),
        port: $('#gSmtpPort').value.trim(),
        secure: $('#gSmtpSecure').checked,
        tlsRejectUnauthorized: $('#gSmtpTlsVerify').checked,
        username: $('#gSmtpUsername').value.trim(),
        from: $('#gSmtpFrom').value.trim(),
        password: $('#gSmtpPassword').value,
      },
    }),
  });
  $('#settingsSaved').classList.remove('hidden');
  setTimeout(() => $('#settingsSaved').classList.add('hidden'), 2000);
  loadSettings();
});

$('#testGlobalEmailBtn').addEventListener('click', async () => {
  const resultEl = $('#globalEmailTestResult');
  resultEl.classList.remove('hidden');
  resultEl.textContent = 'Sending...';
  try {
    const result = await api('/api/admin/alerts/test', { method: 'POST', body: JSON.stringify({}) });
    resultEl.textContent = `✅ Test email sent to: ${result.recipients.join(', ')}`;
  } catch (e) {
    resultEl.textContent = '❌ ' + e.message;
  }
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
  container.innerHTML = `<div class="table-wrap"><table class="table"><thead><tr>
      <th>Time</th><th>Domain</th><th>Event</th><th>Actor</th><th>Target</th><th>Result</th><th>IP</th><th>Detail</th>
    </tr></thead><tbody>${rows.map(auditRowHtml).join('')}</tbody></table></div>`;
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
  container.innerHTML = `<div class="table-wrap"><table class="table"><thead><tr><th>Username</th><th>Created</th><th></th></tr></thead>
    <tbody>${admins.map(a => `<tr>
      <td>${escapeHtml(a.username)}</td>
      <td>${new Date(a.created_at).toLocaleString()}</td>
      <td><button class="btn-link danger" data-del="${a.id}">Delete</button></td>
    </tr>`).join('')}</tbody></table></div>`;
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

// ---------- Email templates ----------

let templatesCache = [];
let activeTemplateKey = null;

async function loadTemplates() {
  try {
    const { dir } = await api('/api/admin/templates-dir');
    $('#templatesDirLabel').textContent = dir;
  } catch (e) { /* non-critical */ }
  templatesCache = await api('/api/admin/templates');
  if (!activeTemplateKey && templatesCache.length) activeTemplateKey = templatesCache[0].key;
  renderTemplateTabs();
  renderTemplateEditor();
}

function renderTemplateTabs() {
  const tabs = $('#templateTabs');
  tabs.innerHTML = templatesCache.map((t) =>
    `<button type="button" class="tab-btn ${t.key === activeTemplateKey ? 'active' : ''}" data-key="${t.key}">${escapeHtml(t.label)}</button>`
  ).join('');
  tabs.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      activeTemplateKey = btn.dataset.key;
      renderTemplateTabs();
      renderTemplateEditor();
    });
  });
}

function renderTemplateEditor() {
  const t = templatesCache.find((x) => x.key === activeTemplateKey);
  const container = $('#templateEditor');
  const badge = $('#templateSourceBadge');
  if (!t) { container.innerHTML = ''; badge.classList.add('hidden'); return; }

  badge.classList.remove('hidden');
  badge.textContent = t.source === 'database' ? 'Custom (saved)' : t.source === 'file' ? 'Custom (file)' : 'Default';
  badge.className = 'badge ' + (t.source === 'default' ? 'badge-disabled' : 'badge-ok');

  container.innerHTML = `
    <label>Subject <input type="text" id="tplSubject" value="${escapeAttr(t.subject)}"/></label>
    <label>Body <textarea id="tplBody" rows="8">${escapeHtml(t.body)}</textarea></label>
    <p class="muted">Available placeholders: ${t.placeholders.map((p) => `<code>{{${p}}}</code>`).join(' ')}</p>
    <div class="modal-actions" style="justify-content:flex-start; gap:10px;">
      <button type="button" id="tplPreviewBtn" class="btn-secondary">Preview with sample data</button>
      <button type="button" id="tplSaveBtn" class="btn-primary">Save</button>
      <button type="button" id="tplResetBtn" class="btn-link danger">Reset to default</button>
    </div>
    <div id="tplPreview" class="hidden" style="margin-top:12px; padding:12px; border:1px solid var(--border); border-radius:8px; background:#f9fafb; white-space:pre-wrap; font-size:13px;"></div>
    <div id="tplError" class="error hidden"></div>
  `;

  $('#tplPreviewBtn').addEventListener('click', async () => {
    try {
      const result = await api(`/api/admin/templates/${t.key}/preview`, {
        method: 'POST',
        body: JSON.stringify({ subject: $('#tplSubject').value, body: $('#tplBody').value }),
      });
      const el = $('#tplPreview');
      el.classList.remove('hidden');
      el.textContent = `Subject: ${result.subject}\n\n${result.body}`;
    } catch (e) {
      $('#tplError').textContent = e.message;
      $('#tplError').classList.remove('hidden');
    }
  });

  $('#tplSaveBtn').addEventListener('click', async () => {
    $('#tplError').classList.add('hidden');
    try {
      await api(`/api/admin/templates/${t.key}`, {
        method: 'PUT',
        body: JSON.stringify({ subject: $('#tplSubject').value, body: $('#tplBody').value }),
      });
      await loadTemplates();
    } catch (e) {
      $('#tplError').textContent = e.message;
      $('#tplError').classList.remove('hidden');
    }
  });

  $('#tplResetBtn').addEventListener('click', async () => {
    if (!confirm('Reset this template to its default? Any saved or file-based override for the subject/body will stop being used.')) return;
    await api(`/api/admin/templates/${t.key}`, { method: 'DELETE' });
    await loadTemplates();
  });
}

// ---------- Reports ----------

const REPORT_TABS = [
  { key: 'failed-logins', label: 'Failed logins' },
  { key: 'successful-events', label: 'Successful events' },
  { key: 'unsuccessful-actions', label: 'Unsuccessful actions' },
  { key: 'by-user', label: 'By user' },
  { key: 'by-target', label: 'By target account' },
  { key: 'activity-trend', label: 'Activity trend' },
];
let activeReportKey = 'failed-logins';

function initReportTabs() {
  const tabs = $('#reportTabs');
  tabs.innerHTML = REPORT_TABS.map((r) =>
    `<button type="button" class="tab-btn ${r.key === activeReportKey ? 'active' : ''}" data-key="${r.key}">${r.label}</button>`
  ).join('');
  tabs.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      activeReportKey = btn.dataset.key;
      tabs.querySelectorAll('.tab-btn').forEach((b) => b.classList.toggle('active', b === btn));
      updateReportEventTypeFilter();
      loadReportTable();
    });
  });
  updateReportEventTypeFilter();
}

function updateReportEventTypeFilter() {
  const wrap = $('#reportEventTypeWrap');
  const select = $('#reportEventTypeFilter');
  if (activeReportKey === 'successful-events') {
    wrap.classList.remove('hidden');
    select.innerHTML = '<option value="">All</option>' +
      ['login', 'logout', 'search', 'unlock', 'reset_password'].map((v) => `<option value="${v}">${v}</option>`).join('');
  } else if (activeReportKey === 'unsuccessful-actions') {
    wrap.classList.remove('hidden');
    select.innerHTML = '<option value="">Unlock + reset password</option>' +
      ['unlock', 'reset_password'].map((v) => `<option value="${v}">${v}</option>`).join('');
  } else {
    wrap.classList.add('hidden');
  }
}

function reportQueryParams(extra = {}) {
  const params = new URLSearchParams();
  const domainId = $('#reportDomainFilter').value;
  const from = $('#reportFrom').value;
  const to = $('#reportTo').value;
  const eventType = $('#reportEventTypeFilter').value;
  if (domainId) params.set('domainId', domainId);
  if (from) params.set('from', from);
  if (to) params.set('to', to + 'T23:59:59.999Z');
  if (eventType) params.set('eventType', eventType);
  Object.entries(extra).forEach(([k, v]) => params.set(k, v));
  return params;
}

function renderReportDomainOptions() {
  const select = $('#reportDomainFilter');
  const current = select.value;
  select.innerHTML = '<option value="">All domains</option><option value="unmatched">Unmatched domain attempts</option>' +
    domainsCache.map((d) => `<option value="${d.id}">${escapeHtml(d.name)} (${escapeHtml(d.domain_suffix)})</option>`).join('');
  select.value = current;
}

async function loadReports() {
  renderReportDomainOptions();
  await loadReportStats();
  await loadReportTable();
}

async function loadReportStats() {
  const params = reportQueryParams();
  const stats = await api('/api/admin/reports/summary?' + params.toString());
  const container = $('#reportStats');
  const boxes = [
    ['Successful logins', stats.logins_success],
    ['Failed logins', stats.logins_failed],
    ['Unlocks performed', stats.unlocks],
    ['Password resets', stats.resets],
    ['Active users', stats.active_users],
    ['Distinct source IPs', stats.distinct_ips],
  ];
  container.innerHTML = boxes.map(([label, num]) =>
    `<div class="stat-box"><div class="num">${num}</div><div class="label">${label} (last ${stats.days}d unless filtered)</div></div>`
  ).join('');
}

async function loadReportTable() {
  const params = reportQueryParams();
  const rows = await api(`/api/admin/reports/${activeReportKey}?` + params.toString());
  const container = $('#reportTable');
  if (!rows.length) {
    container.innerHTML = '<div class="muted">No data for the selected filters.</div>';
    return;
  }
  const headers = Object.keys(rows[0]);
  container.innerHTML = `<div class="table-wrap"><table class="table"><thead><tr>${headers.map((h) => `<th>${escapeHtml(h)}</th>`).join('')}</tr></thead>
    <tbody>${rows.map((r) => `<tr>${headers.map((h) => `<td>${escapeHtml(r[h])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
}

$('#refreshReportsBtn').addEventListener('click', loadReports);
$('#reportDomainFilter').addEventListener('change', loadReports);
$('#downloadReportBtn').addEventListener('click', () => {
  const params = reportQueryParams();
  window.location.href = `/api/admin/reports/${activeReportKey}/export?` + params.toString();
});

checkSession();
