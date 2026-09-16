/* Workspace shell. Existing detection and drawer ownership stays in app.js. */
(() => {
  'use strict';
  const get = id => document.getElementById(id);
  const icon = name => '<i data-lucide="' + esc(name) + '" aria-hidden="true"></i>';
  const icons = () => { if (window.lucide) window.lucide.createIcons(); };
  const views = [
    ['overview', 'Overview', 'layout-dashboard'], ['antivirus', 'Antivirus', 'shield-check'],
    ['ids', 'IDS', 'radar'], ['response', 'IPS / Response', 'shield-alert'],
    ['inventory', 'Inventory', 'network'], ['playbooks', 'Playbooks', 'workflow'],
    ['analysis', 'Analysis Lab', 'flask-conical'], ['training', 'Training', 'users'],
    ['integrations', 'Integrations', 'plug'], ['audit', 'Audit / Logs', 'scroll-text']
  ];
  let active = 'overview';
  let busyPoll = false;
  let lastSensorUpdate = 0;
  const loaded = new Set();
  const jobStates = new Map();
  const book = { steps: [], skills: [], saved: [], findings: [], simulated: '' };
  const game = { scenarios: [], index: 0, turn: 0, scores: [0, 0], answers: [], phase: 'answer', result: null, pending: false };
  const main = document.querySelector('main');
  const legacy = document.createElement('div');
  legacy.hidden = true;
  legacy.id = 'legacy-storage';
  main.append(legacy);
  const move = (selector, target) => {
    const node = document.querySelector(selector);
    if (node) get(target).append(node);
  };
  const panel = (title, html, tag = '') => '<section class="panel"><div class="panel-head"><h2>' +
    title + '</h2>' + (tag ? '<span class="tag">' + tag + '</span>' : '') +
    '</div><div class="tool-body">' + html + '</div></section>';
  const output = (id, data) => { get(id).textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2); };
  async function request(path, payload) {
    const data = payload === undefined ? await api(path) : await post(path, payload);
    if (data.ok === false) throw new Error(data.error || data.refused || 'Request refused');
    return data;
  }
  function action(id, fn, out) {
    get(id).addEventListener('click', async () => {
      const button = get(id);
      button.disabled = true;
      try { await fn(); }
      catch (error) { if (out) output(out, error.message); else toast(error.message, true); }
      finally {
        button.disabled = id === 'book-execute' ? !book.simulated : false;
        if (id === 'inventory-start' || id === 'inventory-cancel') inventory().catch(() => {});
      }
    });
  }
  get('console-nav').innerHTML = '<div class="nav-brand">' + icon('shield') +
    '<span>Security Suite</span></div>' + views.map(([id, label, glyph]) =>
      '<button data-view="' + id + '" title="' + label + '" aria-label="' + label + '">' + icon(glyph) +
      '<span>' + label + '</span></button>').join('') +
    '<div class="nav-foot">Local workspace<br>Evidence before action</div>';
  const header = document.createElement('div');
  header.className = 'workspace-header';
  header.innerHTML = '<div><h1 id="workspace-title">Overview</h1><p id="workspace-description">Local detection and response activity</p></div>' +
    '<button id="density-toggle" aria-pressed="false" title="TV density">' + icon('monitor') + '<span>TV density</span></button>';
  main.prepend(header);
  const tabs = document.createElement('div');
  tabs.className = 'workspace-tabs';
  tabs.setAttribute('role', 'tablist');
  tabs.setAttribute('aria-label', 'Workspace views');
  tabs.innerHTML = views.map(([id, label]) => '<button role="tab" id="tab-' + id +
    '" aria-controls="view-' + id + '" data-view="' + id + '">' + label + '</button>').join('');
  header.after(tabs);
  views.forEach(([id]) => {
    const section = document.createElement('section');
    section.id = 'view-' + id;
    section.className = 'console-view';
    section.setAttribute('role', 'tabpanel');
    section.setAttribute('aria-labelledby', 'tab-' + id);
    section.hidden = true;
    section.innerHTML = '<div class="view-grid"><div class="view-main" id="main-' + id +
      '"></div><aside class="view-side" id="side-' + id + '"></aside></div>';
    tabs.after(section);
  });
  move('.mission-grid', 'legacy-storage');
  move('.kpi-grid', 'view-overview');
  get('view-overview').prepend(document.querySelector('.kpi-grid'));
  move('.findings-panel', 'main-overview');
  move('.lower-panels .compact-panel', 'main-overview');
  move('.lower-panels .compact-panel', 'main-audit');
  move('#sev-breakdown', 'legacy-storage');
  // Move whole panels, then return the detached breakdown body to its panel.
  const severityPanel = [...document.querySelectorAll('.sidebar .panel')].find(p => p.querySelector('h2')?.textContent === 'Severity breakdown');
  if (severityPanel) { get('side-overview').append(severityPanel); severityPanel.append(get('sev-breakdown')); }
  move('#top-rules', 'legacy-storage');
  const rulesPanel = [...document.querySelectorAll('.sidebar .panel')].find(p => p.querySelector('h2')?.textContent === 'Top rules');
  if (rulesPanel) { get('side-overview').append(rulesPanel); rulesPanel.querySelector('.body').append(get('top-rules')); }
  ['telemetry', 'rules-list', 'sensor'].forEach((id, i) => {
    const node = get(id)?.closest('.panel');
    if (node) get(i === 0 ? 'side-ids' : 'side-antivirus').append(node);
  });
  move('.scan-panel', 'main-antivirus');
  move('.ioc-panel', 'main-analysis');
  move('.remediation-panel', 'main-response');
  move('.source-strip', 'main-integrations');
  move('.shield-panel', 'main-integrations');
  get('shield-score').hidden = true;
  get('empty').innerHTML = '<b>No findings</b><span>No findings match the current filters. Detection results do not certify protection.</span>';
  document.querySelector('.footer').innerHTML = '<span>Security Suite / Local console</span><span>Detection, evidence and bounded response</span>';
  document.querySelector('.brand-name').textContent = 'Local sensor';
  ['.workspace-grid', '.lower-panels'].forEach(selector => {
    const node = document.querySelector(selector);
    if (node) legacy.append(node);
  });
  get('main-antivirus').insertAdjacentHTML('beforeend', panel('Scan jobs',
    '<div class="form-row"><label class="field">Drive<select id="drive-select"><option value="">Select a drive</option></select></label>' +
    '<button id="scan-drive" class="action-btn">' + icon('scan-line') + 'Scan drive</button></div>' +
    '<div id="jobs-status" class="status-line">Loading jobs...</div><div id="jobs-list"></div><div id="jobs-error" class="result-box" role="status"></div>'));
  get('main-ids').innerHTML = panel('Imported network alerts',
    '<div class="status-line">Suricata EVE evidence import. Imported alerts are observations, not live network enforcement.</div>' +
    '<label>EVE NDJSON<textarea id="eve-text" spellcheck="false" placeholder="Paste Suricata EVE alert records"></textarea></label>' +
    '<button id="eve-import" class="action-btn">' + icon('file-input') + 'Import alerts</button><div id="eve-result" class="result-box" role="status"></div>' +
    '<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Signature</th><th>Source</th><th>Destination</th><th>Observed action</th></tr></thead><tbody id="ids-rows"></tbody></table></div>');
  get('side-response').innerHTML = panel('Automatic quarantine',
    '<label class="form-row"><input id="policy-enabled" type="checkbox" disabled>Enable automatic quarantine</label>' +
    '<div id="policy-detail" class="status-line">Loading policy...</div><div id="policy-result" class="result-box" role="status"></div>') +
    panel('Reviewed DNS list', '<div class="status-line">Saved list and hosts-file export only. No DNS filtering or ad blocking is enforced.</div>' +
    '<label>Domains<textarea id="domain-text" spellcheck="false" placeholder="One reviewed domain per line"></textarea></label>' +
    '<div class="form-row"><button id="domains-save" class="action-btn">' + icon('save') + 'Save list</button>' +
    '<a href="/api/domains/export" download>Download hosts list</a></div><div id="domains-result" class="result-box" role="status"></div>');
  get('main-inventory').innerHTML = panel('Network inventory',
    '<div class="form-row"><label class="field">Private IPv4 scope<input id="inventory-cidr" placeholder="192.168.1.0/24" autocomplete="off"></label>' +
    '<label><input id="inventory-services" type="checkbox">Check service ports</label></div>' +
    '<div class="form-row"><button id="inventory-start" class="action-btn">' + icon('radar') + 'Discover devices</button>' +
    '<button id="inventory-cancel" disabled>' + icon('square') + 'Cancel</button>' +
    '<a href="/api/inventory/export" download>Export CSV</a></div>' +
    '<div class="status-line">Explicit private network discovery, /24 through /32. Service names are port labels; neighbor entries may be stale.</div>' +
    '<div id="inventory-status" class="status-line"></div><div id="inventory-error" class="result-box" role="status"></div>' +
    '<div class="table-wrap"><table><thead><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Service ports</th><th>Last seen</th></tr></thead><tbody id="inventory-rows"></tbody></table></div>');
  get('main-playbooks').innerHTML = panel('Playbook builder',
    '<div class="form-row"><a href="/playbook.schema.json" target="_blank" rel="noreferrer">Version 1 JSON schema</a>' +
    '<button id="book-export">' + icon('download') + 'Export JSON</button></div>' +
    '<label class="field">Import plan JSON<input id="book-import" type="file" accept="application/json,.json"></label>' +
    '<div class="status-line">External agents can author plans against the schema. No AI service is connected. Imported plans use the same server validation and action allowlist.</div>' +
    '<div class="form-row"><label class="field">Saved playbook<select id="book-saved"><option value="">New playbook</option></select></label>' +
    '<button id="book-new">' + icon('plus') + 'New</button></div>' +
    '<div class="form-row"><label class="field">ID<input id="book-id" value="response-review" maxlength="64"></label>' +
    '<label class="field">Name<input id="book-name" value="Review detected file" maxlength="120"></label></div>' +
    '<div class="finding-drop" id="finding-drop"><label class="field">Finding<select id="book-finding"><option value="">Select a stored detection</option></select></label>' +
    '<div id="finding-summary" class="hint">No finding selected</div></div>' +
    '<div class="step-list" id="book-steps"></div><div class="form-row">' +
    '<button id="book-validate">' + icon('check') + 'Validate</button><button id="book-save">' + icon('save') + 'Save</button>' +
    '<button id="book-simulate" class="action-btn">' + icon('play') + 'Simulate</button>' +
    '<button id="book-execute" class="danger-btn" disabled>' + icon('shield-alert') + 'Execute</button></div>' +
    '<div id="book-result" class="result-box" role="status"></div>');
  get('side-playbooks').innerHTML = panel('Allowed skills', '<div class="skill-list" id="book-skills"></div>', '12 steps maximum');
  get('main-analysis').insertAdjacentHTML('afterbegin', panel('Text analysis',
    '<div class="status-line">Static YARA and indicator inspection. Pasted text is never executed or persisted.</div>' +
    '<label>Evidence<textarea id="analysis-text" spellcheck="false" maxlength="48000" placeholder="Paste suspicious text for static inspection"></textarea></label>' +
    '<button id="analysis-run" class="action-btn">' + icon('search') + 'Analyze text</button><div id="analysis-result" class="result-box" role="status"></div>'));
  get('main-training').innerHTML = panel('Local pass-and-play',
    '<div class="status-line">Two players on this device. Synthetic tabletop decisions; no attack payloads or online multiplayer.</div>' +
    '<div id="training-game"></div><div id="training-result" class="result-box" role="status"></div>' +
    '<div class="form-row"><button id="training-next" hidden>' + icon('arrow-right') + 'Pass device</button>' +
    '<button id="training-reset">' + icon('rotate-ccw') + 'Reset game</button></div>');
  get('side-integrations').innerHTML = panel('Endpoint registration',
    '<div id="native-av-status" class="status-line">Not checked</div><button id="native-av-check">' + icon('refresh-cw') +
    'Check Windows registration</button><div id="native-av-result" class="result-box" role="status"></div>') +
    panel('Connector status', '<div id="connectors-status" class="status-line">Loading connector configuration...</div>' +
    '<button id="connectors-check">' + icon('refresh-cw') + 'Check OPNsense service</button>' +
    '<div class="hint">Read-only service health. Configuration and a running IDS service do not attest to IPS enforcement or network protection. Bitdefender is setup status only.</div>' +
    '<div id="connectors-result" class="result-box" role="status"></div>');
  move('#refresh-intel', 'side-integrations');
  move('#intel-sync', 'side-integrations');
  get('refresh-intel').innerHTML = icon('refresh-cw') + 'Refresh intelligence status';
  get('audio-toggle').prepend(Object.assign(document.createElement('i'), { innerHTML: '' }));
  get('audio-toggle').firstElementChild.setAttribute('data-lucide', 'volume-2');
  ['q', 'f-sev', 'f-status', 'f-type', 'scan-path', 'ioc-type', 'rem-severity', 'rem-ext', 'rem-action'].forEach(id => {
    get(id).setAttribute('aria-label', { q: 'Search findings', 'f-sev': 'Finding severity', 'f-status': 'Finding status',
      'f-type': 'Event type', 'scan-path': 'File or folder path', 'ioc-type': 'Indicator type',
      'rem-severity': 'Response severity', 'rem-ext': 'File extensions', 'rem-action': 'Response action' }[id]);
  });
  get('main-audit').insertAdjacentHTML('afterbegin', panel('Activity and response log',
    '<div class="status-line">Stored findings and response actions. Live feed shows received events while this console is open.</div>' +
    '<button id="audit-refresh">' + icon('refresh-cw') + 'Refresh logs</button><div id="audit-error" class="result-box" role="status"></div>' +
    '<div class="table-wrap"><table><thead><tr><th>Time</th><th>Event</th><th>Detail</th><th>Status</th></tr></thead><tbody id="audit-rows"></tbody></table></div>'));
  get('side-audit').innerHTML = panel('Recent response actions', '<div id="audit-actions"></div>');

  const descriptions = {
    overview: 'Local detection and response activity', antivirus: 'File inspection and bounded scan jobs',
    ids: 'Network evidence and identity telemetry', response: 'File containment and reviewed policy',
    inventory: 'Explicit discovery on your private network', playbooks: 'Ordered response skills for stored detections',
    analysis: 'Static evidence inspection', training: 'Synthetic tabletop decisions on this device',
    integrations: 'Registration, configuration and service health', audit: 'Recorded activity and response outcomes'
  };
  function navigate(id) {
    if (!views.some(v => v[0] === id)) id = 'overview';
    active = id;
    views.forEach(([key]) => {
      get('view-' + key).hidden = key !== id;
      get('tab-' + key).setAttribute('aria-selected', String(key === id));
      get('tab-' + key).tabIndex = key === id ? 0 : -1;
      const nav = document.querySelector('.console-nav [data-view="' + key + '"]');
      if (key === id) nav.setAttribute('aria-current', 'page'); else nav.removeAttribute('aria-current');
    });
    get('workspace-title').textContent = views.find(v => v[0] === id)[1];
    get('workspace-description').textContent = descriptions[id];
    history.replaceState(null, '', '#' + id);
    poll();
  }
  document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => navigate(button.dataset.view)));
  tabs.addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const index = views.findIndex(v => v[0] === active);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? views.length - 1 :
      (index + (event.key === 'ArrowRight' ? 1 : -1) + views.length) % views.length;
    navigate(views[next][0]); get('tab-' + views[next][0]).focus();
  });
  window.addEventListener('hashchange', () => navigate(location.hash.slice(1)));
  function density(value) {
    document.body.classList.toggle('density-tv', value);
    get('density-toggle').setAttribute('aria-pressed', String(value));
    localStorage.setItem('suite-tv-density', String(value));
  }
  density(localStorage.getItem('suite-tv-density') === 'true');
  get('density-toggle').addEventListener('click', () => density(!document.body.classList.contains('density-tv')));

  async function jobs() {
    const data = await request('/api/jobs');
    let finished = false;
    data.jobs.forEach(job => {
      const before = jobStates.get(job.id);
      if (before && ['queued', 'running', 'cancelling'].includes(before) &&
          !['queued', 'running', 'cancelling'].includes(job.state)) finished = true;
      jobStates.set(job.id, job.state);
    });
    if (finished) { loadFindings(); loadIocs(); loadRemediation(); }
    get('jobs-status').textContent = data.jobs.length + ' recorded scan job(s)';
    get('jobs-list').innerHTML = data.jobs.map(job => '<div class="job"><div class="job-head"><div class="job-path">' +
      esc(job.path) + '<br><span class="tag">' + esc(job.state) + '</span></div>' +
      (['queued', 'running'].includes(job.state) ? '<button data-cancel-job="' + esc(job.id) + '">' + icon('square') + 'Cancel</button>' : '') +
      '</div><small>' + esc(job.scanned) + ' scanned / ' + esc(job.matches) + ' matches / ' + esc(job.skipped) + ' skipped / ' +
      esc(job.errors) + ' errors</small>' + (job.current_path ? '<small>' + esc(job.current_path) + '</small>' : '') +
      (job.error ? '<small class="err">' + esc(job.error) + '</small>' : '') +
      (Object.keys(job.skip_reasons || {}).length ? '<small>Skip reasons: ' + esc(JSON.stringify(job.skip_reasons)) + '</small>' : '') + '</div>').join('') ||
      '<div class="empty"><b>No scan jobs</b><span>Select a drive to start a scan.</span></div>';
    output('jobs-error', ''); icons();
  }
  action('scan-drive', async () => {
    const path = get('drive-select').value;
    if (!path) throw new Error('Select a drive first');
    await request('/api/jobs', { path }); await jobs();
  }, 'jobs-error');
  get('jobs-list').addEventListener('click', async event => {
    const button = event.target.closest('[data-cancel-job]');
    if (!button) return;
    button.disabled = true;
    try { await request('/api/jobs/cancel', { id: button.dataset.cancelJob }); await jobs(); }
    catch (error) { output('jobs-error', error.message); button.disabled = false; }
  });
  async function ids() {
    const data = await request('/api/ids');
    get('ids-rows').innerHTML = data.alerts.map(alert => '<tr><td>' + esc(alert.severity) + '</td><td>' + esc(alert.message) +
      '</td><td>' + esc(alert.src_ip) + '</td><td>' + esc(alert.dest_ip) + '</td><td>' + esc(alert.network_action) + '</td></tr>').join('') ||
      '<tr><td colspan="5" class="faint">No imported alerts</td></tr>';
  }
  action('eve-import', async () => { output('eve-result', await request('/api/ids/import', { text: get('eve-text').value })); await ids(); }, 'eve-result');
  async function workspace() {
    const data = await request('/api/workspace');
    get('policy-enabled').checked = !!data.policy.enabled;
    get('policy-enabled').disabled = false;
    get('policy-detail').textContent = 'Quarantine at ' + data.policy.severity + '. Rule opt-in: ' +
      (data.policy.requires_rule_opt_in ? 'required' : 'not required') + '. Permitted roots: ' + (data.policy.roots || []).join(', ');
    if (!loaded.has('domains')) { get('domain-text').value = (data.domains || []).join('\n'); loaded.add('domains'); }
    get('native-av-status').textContent = data.native_av.status + '. ' + (data.native_av.detail || 'Registration is not a protection attestation.');
  }
  get('policy-enabled').addEventListener('change', async () => {
    const input = get('policy-enabled'), enabled = input.checked;
    if (enabled && !confirm('Enable automatic quarantine for opted-in rules within the permitted roots?')) { input.checked = false; return; }
    input.disabled = true;
    try { await request('/api/policy', { enabled }); output('policy-result', 'Automatic quarantine ' + (enabled ? 'enabled' : 'disabled')); }
    catch (error) { input.checked = !enabled; output('policy-result', error.message); }
    finally { input.disabled = false; }
  });
  action('domains-save', async () => { const data = await request('/api/domains', { text: get('domain-text').value });
    get('domain-text').value = data.domains.join('\n'); output('domains-result', data.domains.length + ' reviewed domain(s) saved. Enforcement is off.'); }, 'domains-result');
  action('native-av-check', async () => { output('native-av-result', await request('/api/native-av', {})); await workspace(); }, 'native-av-result');
  async function inventory() {
    const data = await request('/api/inventory');
    const running = ['running', 'cancelling'].includes(data.state);
    get('inventory-start').disabled = running;
    get('inventory-cancel').disabled = data.state !== 'running';
    get('inventory-status').textContent = data.state + (data.scope ? ' / ' + data.scope : '') + ' / ' + data.devices.length +
      ' observed device(s)' + (data.last_scan ? ' / last scan ' + data.last_scan : '');
    output('inventory-error', data.error || '');
    get('inventory-rows').innerHTML = data.devices.map(device => '<tr><td>' + esc(device.ip) + '</td><td>' + esc(device.hostname || 'Unknown') +
      '</td><td>' + esc(device.mac || 'Unknown') + '</td><td>' + esc(device.services.map(s => s.port + ' / ' + s.name).join(', ') || 'Not observed') +
      '</td><td>' + esc(device.last_seen) + '</td></tr>').join('') || '<tr><td colspan="5" class="faint">No devices observed. Discovery starts only when requested.</td></tr>';
  }
  action('inventory-start', async () => { await request('/api/inventory', { cidr: get('inventory-cidr').value.trim(), services: get('inventory-services').checked }); await inventory(); }, 'inventory-error');
  action('inventory-cancel', async () => { await request('/api/inventory/cancel', {}); await inventory(); }, 'inventory-error');
  action('analysis-run', async () => { output('analysis-result', await request('/api/analysis', { text: get('analysis-text').value })); }, 'analysis-result');
  async function connectors() {
    const data = await request('/api/connectors');
    // Keep every returned state visible without interpreting configured as protected.
    output('connectors-status', JSON.stringify(data, null, 2));
    get('connectors-status').style.whiteSpace = 'pre-wrap';
    get('connectors-status').style.overflowWrap = 'anywhere';
  }
  action('connectors-check', async () => { output('connectors-result', await request('/api/connectors/check', {})); await connectors(); }, 'connectors-result');

  function invalidate() { book.simulated = ''; get('book-execute').disabled = true; }
  function definition() {
    const value = { id: get('book-id').value.trim(), name: get('book-name').value.trim(), version: 1,
      steps: book.steps.map(step => ({ ...step })) };
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(value.id)) throw new Error('ID must use 1-64 letters, numbers, underscores or hyphens');
    if (!value.name || value.name.length > 120) throw new Error('Enter a name of 1-120 characters');
    if (!value.steps.length || value.steps.length > 12) throw new Error('Add 1-12 allowed skills');
    value.steps.forEach(step => {
      if (!['annotate', 'guidance', 'quarantine'].includes(step.action)) throw new Error('Unsupported skill');
      if (step.action === 'annotate' && (!step.note.trim() || step.note.length > 2000)) throw new Error('Each annotation needs 1-2000 characters');
    });
    return value;
  }
  function validateImported(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value) ||
        Object.keys(value).some(key => !['id', 'name', 'version', 'steps'].includes(key)) ||
        typeof value.id !== 'string' || typeof value.name !== 'string' || value.version !== 1 || !Array.isArray(value.steps))
      throw new Error('Plan must contain only version: 1, id, name and steps');
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(value.id) || !value.name.trim() || value.name.length > 120 ||
        value.steps.length < 1 || value.steps.length > 12) throw new Error('Invalid plan ID, name or step count');
    value.steps.forEach(step => {
      if (!step || typeof step !== 'object' || Array.isArray(step) || !['annotate', 'guidance', 'quarantine'].includes(step.action))
        throw new Error('Only annotate, guidance and quarantine steps are accepted');
      const allowed = step.action === 'annotate' ? ['action', 'note', 'status'] : ['action'];
      if (Object.keys(step).some(key => !allowed.includes(key))) throw new Error('Unexpected step property');
      if (step.action === 'annotate' && (typeof step.note !== 'string' || !step.note.trim() || step.note.length > 2000 ||
          ('status' in step && !['new', 'acknowledged', 'resolved', 'false_positive'].includes(step.status))))
        throw new Error('Annotation needs a literal note and an allowed optional status');
    });
    if (new TextEncoder().encode(JSON.stringify(value)).length > 32768) throw new Error('Plan exceeds 32 KB');
    return value;
  }
  get('book-import').addEventListener('change', async event => {
    const file = event.target.files[0];
    if (!file) return;
    try {
      if (file.size > 32768) throw new Error('Import accepts JSON files up to 32 KB');
      const value = validateImported(JSON.parse(await file.text()));
      get('book-id').value = value.id; get('book-name').value = value.name; get('book-saved').value = '';
      book.steps = value.steps.map(step => ({ ...step })); invalidate(); renderSteps();
      output('book-result', 'Imported ' + value.name + '. Save or simulate to apply server validation.');
    } catch (error) { output('book-result', error.message); }
    finally { event.target.value = ''; }
  });
  action('book-export', async () => {
    const value = validateImported(definition());
    const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url; link.download = value.id + '.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    output('book-result', 'Exported version 1 plan');
  }, 'book-result');
  function signature() { return JSON.stringify({ playbook: definition(), finding_id: get('book-finding').value }); }
  function renderSteps() {
    get('book-steps').innerHTML = book.steps.map((step, index) => '<div class="step" draggable="true" data-step="' + index + '"><div class="step-head">' +
      icon('grip-vertical') + '<strong>' + esc(index + 1) + '. ' + esc(book.skills.find(s => s.action === step.action)?.label || step.action) + '</strong>' +
      '<button class="icon-only" data-step-up="' + index + '" title="Move up" aria-label="Move step up"' + (index === 0 ? ' disabled' : '') + '>' + icon('arrow-up') + '</button>' +
      '<button class="icon-only" data-step-down="' + index + '" title="Move down" aria-label="Move step down"' + (index === book.steps.length - 1 ? ' disabled' : '') + '>' + icon('arrow-down') + '</button>' +
      '<button class="icon-only" data-step-remove="' + index + '" title="Remove skill" aria-label="Remove skill">' + icon('x') + '</button></div>' +
      (step.action === 'annotate' ? '<textarea data-note="' + index + '" aria-label="Triage note" maxlength="2000">' + esc(step.note) + '</textarea>' +
      '<select data-status="' + index + '" aria-label="Triage status">' + ['', 'new', 'acknowledged', 'resolved', 'false_positive'].map(s =>
        '<option value="' + s + '"' + (s === (step.status || '') ? ' selected' : '') + '>' + esc(s || 'Preserve status') + '</option>').join('') + '</select>' : '') + '</div>').join('') ||
      '<div class="empty"><b>No steps</b><span>Add an allowed skill</span></div>';
    icons();
  }
  function addSkill(actionName) {
    if (!book.skills.some(s => s.action === actionName) || !['annotate', 'guidance', 'quarantine'].includes(actionName)) return;
    if (book.steps.length >= 12) { output('book-result', 'Maximum 12 steps'); return; }
    book.steps.push(actionName === 'annotate' ? { action: actionName, note: '' } : { action: actionName }); invalidate(); renderSteps();
  }
  async function playbooks() {
    const data = await request('/api/playbooks');
    book.skills = data.skills.filter(s => ['annotate', 'guidance', 'quarantine'].includes(s.action));
    book.saved = data.playbooks;
    const chosen = get('book-saved').value;
    get('book-saved').innerHTML = '<option value="">New playbook</option>' + book.saved.map(p => '<option value="' + esc(p.id) + '">' + esc(p.name) + '</option>').join('');
    get('book-saved').value = chosen;
    get('book-skills').innerHTML = book.skills.map(skill => '<button draggable="true" data-skill="' + esc(skill.action) + '" title="' + esc(skill.description) + '">' +
      icon('plus') + esc(skill.label) + '<small>' + esc(skill.description) + '</small></button>').join('');
    if (data.error) output('book-result', data.error);
    icons();
  }
  async function findingOptions() {
    const data = await request('/api/findings?type=yara_match&limit=300');
    book.findings = (data.findings || []).filter(f => f.event_type === 'yara_match');
    const chosen = get('book-finding').value;
    get('book-finding').innerHTML = '<option value="">Select a stored detection</option>' + book.findings.map(f =>
      '<option value="' + esc(f.id) + '">' + esc((f.severity || '') + ' / ' + (f.file_path || f.id)) + '</option>').join('');
    get('book-finding').value = chosen;
    if (chosen !== get('book-finding').value) invalidate();
    findingSummary();
  }
  function findingSummary() {
    const finding = book.findings.find(f => f.id === get('book-finding').value);
    get('finding-summary').textContent = finding ? finding.id + ' / ' + (finding.rule_names || []).join(', ') : 'No finding selected';
  }
  get('book-skills').addEventListener('click', event => { const button = event.target.closest('[data-skill]'); if (button) addSkill(button.dataset.skill); });
  get('book-steps').addEventListener('click', event => {
    const button = event.target.closest('button'); if (!button) return;
    const remove = button.dataset.stepRemove;
    if (remove !== undefined) book.steps.splice(Number(remove), 1);
    else {
      const index = Number(button.dataset.stepUp ?? button.dataset.stepDown), target = index + (button.dataset.stepUp !== undefined ? -1 : 1);
      if (target < 0 || target >= book.steps.length) return;
      [book.steps[index], book.steps[target]] = [book.steps[target], book.steps[index]];
    }
    invalidate(); renderSteps();
  });
  get('book-steps').addEventListener('input', event => {
    const index = event.target.dataset.note;
    if (index !== undefined) { book.steps[Number(index)].note = event.target.value; invalidate(); }
  });
  get('book-steps').addEventListener('change', event => {
    const index = event.target.dataset.status;
    if (index !== undefined) {
      if (event.target.value) book.steps[Number(index)].status = event.target.value; else delete book.steps[Number(index)].status;
      invalidate();
    }
  });
  ['book-id', 'book-name', 'book-finding'].forEach(id => get(id).addEventListener('input', () => { invalidate(); findingSummary(); }));
  get('book-finding').addEventListener('change', () => { invalidate(); findingSummary(); });
  get('book-saved').addEventListener('change', () => {
    const selected = book.saved.find(p => p.id === get('book-saved').value);
    if (selected) { get('book-id').value = selected.id; get('book-name').value = selected.name; book.steps = selected.steps.map(s => ({ ...s })); }
    else { book.steps = []; }
    invalidate(); renderSteps(); output('book-result', '');
  });
  get('book-new').addEventListener('click', () => {
    get('book-saved').value = ''; get('book-id').value = 'response-' + Date.now(); get('book-name').value = 'New response playbook';
    book.steps = []; invalidate(); renderSteps(); output('book-result', '');
  });
  action('book-validate', async () => { definition(); output('book-result', 'Valid version 1 definition. Only annotate, guidance and quarantine are allowed.'); }, 'book-result');
  action('book-save', async () => { const data = await request('/api/playbooks/save', definition()); await playbooks(); get('book-saved').value = data.playbook.id;
    output('book-result', 'Saved ' + data.playbook.name); }, 'book-result');
  action('book-simulate', async () => {
    invalidate(); const snapshot = signature();
    if (!get('book-finding').value) throw new Error('Select a stored detection first');
    const data = await request('/api/playbooks/run', { playbook: definition(), finding_id: get('book-finding').value, dry_run: true, confirm: false });
    output('book-result', data);
    if (signature() === snapshot) { book.simulated = snapshot; get('book-execute').disabled = false; }
  }, 'book-result');
  action('book-execute', async () => {
    if (!book.simulated || book.simulated !== signature()) throw new Error('Simulate this exact playbook and finding before execution');
    const value = definition();
    if (!confirm('Execute ' + value.name + ' on the selected stored finding?\nAnnotations update triage. Quarantine moves the file through existing safety checks. Completed steps are not rolled back.')) return;
    invalidate(); output('book-result', await request('/api/playbooks/run', { playbook: value, finding_id: get('book-finding').value, dry_run: false, confirm: true }));
    await findingOptions(); loadFindings(); loadRemediation();
  }, 'book-result');
  // Dedicated MIME types keep dropped data literal and limited to known IDs/actions.
  document.addEventListener('dragstart', event => {
    const row = event.target.closest('#rows tr[data-id]');
    const skill = event.target.closest('[data-skill]');
    const step = event.target.closest('[data-step]');
    if (row) event.dataTransfer.setData('application/x-suite-finding', row.dataset.id);
    else if (skill) event.dataTransfer.setData('application/x-suite-skill', skill.dataset.skill);
    else if (step && !event.target.closest('textarea,select,input')) event.dataTransfer.setData('application/x-suite-step', step.dataset.step);
    else return;
    event.dataTransfer.effectAllowed = row || skill ? 'copy' : 'move';
  });
  const makeRowsDraggable = () => document.querySelectorAll('#rows tr[data-id]').forEach(row => { row.draggable = true; row.title = 'Open finding or drag to Playbooks'; });
  new MutationObserver(makeRowsDraggable).observe(get('rows'), { childList: true });
  makeRowsDraggable();
  ['finding-drop', 'book-steps'].forEach(id => {
    const target = get(id);
    target.addEventListener('dragover', event => {
      const types = [...event.dataTransfer.types];
      if (!types.some(type => type.startsWith('application/x-suite-'))) return;
      event.preventDefault(); target.classList.add('drop-active');
    });
    target.addEventListener('dragleave', event => { if (!target.contains(event.relatedTarget)) target.classList.remove('drop-active'); });
    target.addEventListener('drop', event => {
      event.preventDefault(); target.classList.remove('drop-active');
      const finding = event.dataTransfer.getData('application/x-suite-finding');
      if (finding && book.findings.some(f => f.id === finding)) { get('book-finding').value = finding; invalidate(); findingSummary(); return; }
      if (id !== 'book-steps') return;
      const skill = event.dataTransfer.getData('application/x-suite-skill');
      if (skill) { addSkill(skill); return; }
      const raw = event.dataTransfer.getData('application/x-suite-step');
      if (!/^\d+$/.test(raw)) return;
      const from = Number(raw), to = Number(event.target.closest('[data-step]')?.dataset.step ?? book.steps.length - 1);
      if (from < book.steps.length && to < book.steps.length) { book.steps.splice(to, 0, book.steps.splice(from, 1)[0]); invalidate(); renderSteps(); }
    });
  });
  // Hover the Playbooks navigation while carrying a finding to expose its drop target.
  let dragNavTimer;
  document.querySelectorAll('[data-view="playbooks"]').forEach(button => {
    button.addEventListener('dragenter', event => {
      if ([...event.dataTransfer.types].includes('application/x-suite-finding')) dragNavTimer = setTimeout(() => navigate('playbooks'), 350);
    });
    button.addEventListener('dragover', event => event.preventDefault());
    button.addEventListener('dragleave', () => clearTimeout(dragNavTimer));
  });

  function renderGame() {
    const scenario = game.scenarios[game.index];
    if (!scenario) { get('training-game').innerHTML = '<div class="empty">No scenarios available</div>'; return; }
    get('training-game').innerHTML = '<div class="scoreboard">' + game.scores.map((score, i) => '<div class="player' +
      (game.turn === i ? ' active' : '') + '">Player ' + (i + 1) + '<strong>' + esc(score) + '</strong></div>').join('') + '</div>' +
      '<div class="status-line">Scenario ' + (game.index + 1) + ' of ' + game.scenarios.length + ' / Player ' + (game.turn + 1) +
      (game.phase === 'pass' ? ' / pass device' : game.phase === 'review' ? ' / round complete' : ' / choose a response') + '</div>' +
      (game.phase === 'answer' ? '<p class="training-question">' + esc(scenario.question) + '</p><div class="choice-list">' + scenario.choices.map(choice =>
        '<button data-answer="' + esc(choice.id) + '"><span class="tag">' + esc(choice.id) + '</span>' + esc(choice.label) + '</button>').join('') + '</div>' :
      '<p class="training-question">' + (game.phase === 'pass' ? 'Player 1 response recorded. Pass this device to Player 2.' : 'Both responses recorded.') + '</p>');
    get('training-next').hidden = game.phase === 'answer';
    get('training-next').innerHTML = icon('arrow-right') + (game.phase === 'pass' ? 'Player 2 ready' : 'Next scenario');
    icons();
  }
  async function training() {
    if (loaded.has('training')) return;
    const data = await request('/api/training'); game.scenarios = data.scenarios; loaded.add('training'); renderGame();
  }
  get('training-game').addEventListener('click', async event => {
    const button = event.target.closest('[data-answer]'); if (!button || game.phase !== 'answer' || game.pending) return;
    game.pending = true; get('training-reset').disabled = true;
    get('training-game').querySelectorAll('[data-answer]').forEach(b => { b.disabled = true; });
    try {
      const data = await request('/api/training/grade', { id: game.scenarios[game.index].id, answer: button.dataset.answer });
      game.answers[game.turn] = data; game.result = data;
      // Withhold correctness and scores until both players have answered.
      if (game.turn === 0) { game.phase = 'pass'; output('training-result', ''); }
      else {
        game.phase = 'review'; game.answers.forEach((answer, i) => { game.scores[i] += Number(answer.score) || 0; });
        output('training-result', game.answers.map((answer, i) => 'Player ' + (i + 1) + ': ' + answer.answer + ' / ' + (answer.correct ? 'Correct' : 'Incorrect')).join('\n') +
          '\nCorrect response: ' + data.correct_answer + '\n' + data.explanation);
      }
      renderGame();
    } catch (error) { output('training-result', error.message); renderGame(); }
    finally { game.pending = false; get('training-reset').disabled = false; }
  });
  get('training-next').addEventListener('click', () => {
    if (game.phase === 'pass') game.turn = 1;
    else {
      if (game.index + 1 >= game.scenarios.length) { output('training-result', 'Session complete. Player 1: ' + game.scores[0] + '. Player 2: ' + game.scores[1]); get('training-next').hidden = true; return; }
      game.index++; game.turn = 0; game.answers = [];
    }
    game.phase = 'answer'; output('training-result', ''); renderGame();
  });
  get('training-reset').addEventListener('click', () => {
    game.index = 0; game.turn = 0; game.scores = [0, 0]; game.answers = []; game.phase = 'answer'; output('training-result', ''); renderGame();
  });
  async function audit() {
    const data = await request('/api/findings?type=all&limit=100');
    get('audit-rows').innerHTML = (data.findings || []).map(event => '<tr><td>' + esc(event.timestamp) + '</td><td>' + esc(event.event_type) +
      '</td><td>' + esc(event.message || event.file_path || (event.rule_names || []).join(', ')) + '</td><td>' + esc(event.status || '') + '</td></tr>').join('') ||
      '<tr><td colspan="4" class="faint">No recorded activity</td></tr>';
    const rem = await request('/api/remediate');
    get('audit-actions').innerHTML = (rem.recent || []).map(item => '<div class="job"><span class="tag">' + esc(item.outcome) + '</span>' +
      '<div class="job-path">' + esc(item.path) + '</div><small>' + esc(item.timestamp) + '</small>' +
      (item.refused ? '<small>' + esc(item.refused) + '</small>' : '') + '</div>').join('') || '<span class="faint">No response actions recorded</span>';
    output('audit-error', '');
  }
  action('audit-refresh', audit, 'audit-error');
  async function poll() {
    if (busyPoll || document.hidden) return;
    busyPoll = true;
    const current = active;
    try {
      if (current === 'overview') {
        await loadFindings();
      } else if (current === 'antivirus') {
        if (!loaded.has('drives')) {
          const data = await request('/api/drives');
          get('drive-select').innerHTML = '<option value="">Select a drive</option>' + data.drives.map(d => '<option value="' + esc(d.path) + '">' +
            esc(d.label + ' / ' + d.path) + '</option>').join(''); loaded.add('drives');
        }
        await jobs();
        if (Date.now() - lastSensorUpdate > 15000) {
          renderSensor(await request('/api/state'));
          lastSensorUpdate = Date.now();
        }
      } else if (current === 'ids') { await ids(); renderTelemetry(await request('/api/telemetry')); }
      else if (current === 'response') { await workspace(); await loadRemediation(); }
      else if (current === 'analysis') await loadIocs();
      else if (current === 'inventory') await inventory();
      else if (current === 'playbooks') { if (!loaded.has('playbooks')) { await playbooks(); loaded.add('playbooks'); } await findingOptions(); }
      else if (current === 'training') await training();
      else if (current === 'integrations') { await workspace(); await connectors(); }
      else if (current === 'audit') await audit();
    } catch (error) {
      const target = { antivirus: 'jobs-error', ids: 'eve-result', response: 'policy-result', inventory: 'inventory-error',
        playbooks: 'book-result', training: 'training-result', integrations: 'connectors-result', audit: 'audit-error' }[current];
      if (target) output(target, error.message);
    } finally { busyPoll = false; if (current !== active) poll(); }
  }
  renderSteps(); icons(); navigate(location.hash.slice(1));
  setInterval(poll, 3000);
  document.addEventListener('suite-scan-started', () => { if (active === 'antivirus') jobs().catch(error => output('jobs-error', error.message)); });
  window.addEventListener('suite-scan-started', () => { if (active === 'antivirus') poll(); });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
})();
