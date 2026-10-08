// Defence Cyber Portal - Interactive Web Application Controller

const state = {
  currentView: 'soc',
  currentRole: 'SOC Analyst',
  currentTenant: 'tenant_acme',
  alerts: [],
  incidents: [],
  selectedIncident: null,
  selectedAlertForTriage: null,
  activePlaybookExecution: null,
  pendingApprovalStep: null,
  ws: null,
  slaInterval: null
};

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initControls();
  initWebSocket();
  loadAllData();

  // Polling SLA timers every 3 seconds
  state.slaInterval = setInterval(refreshSLATimers, 3000);
});

// --- Tabs Routing ---
function initTabs() {
  const buttons = document.querySelectorAll('.tab-button');
  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      const view = btn.getAttribute('data-view');
      switchView(view);
    });
  });
}

function switchView(viewName) {
  state.currentView = viewName;
  document.querySelectorAll('.tab-button').forEach(b => {
    b.classList.toggle('active', b.getAttribute('data-view') === viewName);
  });
  document.querySelectorAll('.view-content').forEach(v => {
    v.classList.toggle('active', v.id === `view-${viewName}`);
  });

  // Trigger view-specific render
  if (viewName === 'soc') renderAlerts();
  if (viewName === 'incidents') renderIncidents();
  if (viewName === 'investigation') renderInvestigation();
  if (viewName === 'playbooks') renderPlaybooks();
  if (viewName === 'commander') renderCommander();
  if (viewName === 'executive') renderExecutive();
  if (viewName === 'audit') renderAudit();
  if (viewName === 'platform') renderPlatform();
}

// --- Controls (Tenant, Role, Simulator, Break-Glass) ---
function initControls() {
  document.getElementById('tenant-select').addEventListener('change', (e) => {
    state.currentTenant = e.target.value;
    showToast(`Tenant scope switched to ${e.target.options[e.target.selectedIndex].text}`);
    loadAllData();
  });

  document.getElementById('role-select').addEventListener('change', (e) => {
    state.currentRole = e.target.value;
    showToast(`Active Role changed to: ${state.currentRole}`);
    renderCurrentView();
  });

  document.getElementById('btn-open-simulator').addEventListener('click', () => {
    openModal('modal-simulator');
  });

  document.getElementById('btn-refresh-alerts').addEventListener('click', loadAlerts);

  // Attack scenario simulation clicks
  document.getElementById('sim-ransomware').addEventListener('click', () => triggerAttack('powershell_ransomware'));
  document.getElementById('sim-phishing').addEventListener('click', () => triggerAttack('phishing_credential'));
  document.getElementById('sim-cloud').addEventListener('click', () => triggerAttack('cloud_iam_privilege'));

  // Break-Glass emergency activation
  document.getElementById('btn-break-glass').addEventListener('click', () => {
    const reason = prompt('Enter justification for BREAK-GLASS emergency authorization (audited with high priority):', 'Urgent P1 Major Incident containment during primary responder outage');
    if (reason) {
      fetch('/api/roles/break-glass', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subjectId: 'emergency-operator', reason, tenantId: state.currentTenant })
      })
      .then(res => res.json())
      .then(data => {
        showToast('🚨 BREAK-GLASS Emergency Administrator privileges activated for 60 minutes!');
        document.getElementById('role-select').value = 'Incident Commander';
        state.currentRole = 'Incident Commander';
        renderCurrentView();
      });
    }
  });

  // Close modals
  document.querySelectorAll('.modal-close').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
    });
  });

  // Triage Escalation / Suppression
  document.getElementById('btn-triage-escalate').addEventListener('click', () => {
    if (!state.selectedAlertForTriage) return;
    triageAlert(state.selectedAlertForTriage.alert_id, 'escalate', 'True Positive');
  });

  document.getElementById('btn-triage-suppress').addEventListener('click', () => {
    if (!state.selectedAlertForTriage) return;
    triageAlert(state.selectedAlertForTriage.alert_id, 'suppress', 'Known Benign');
  });

  // Playbook Step Approval Confirm
  document.getElementById('btn-confirm-approval').addEventListener('click', confirmStepApproval);

  // Audit verify button
  document.getElementById('btn-verify-chain').addEventListener('click', verifyAuditChain);

  // Post-incident report button
  document.getElementById('btn-export-pir').addEventListener('click', openPIRModal);
  document.getElementById('pir-audience-select').addEventListener('change', (e) => loadPIR(e.target.value));

  // Multi-region failover button
  document.getElementById('btn-trigger-failover').addEventListener('click', triggerFailoverPromotion);

  // Declare manual incident button
  document.getElementById('btn-new-incident').addEventListener('click', declareManualIncident);

  // Add analyst note
  document.getElementById('btn-add-note').addEventListener('click', addAnalystNote);

  // Attach evidence
  document.getElementById('btn-attach-evidence').addEventListener('click', attachForensicEvidence);
}

// --- WebSocket Live Stream ---
function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}`;
  state.ws = new WebSocket(wsUrl);

  state.ws.onopen = () => {
    document.getElementById('conn-text').textContent = 'LIVE (Kafka Connected)';
    document.getElementById('conn-badge').style.borderColor = 'rgba(16, 185, 129, 0.4)';
  };

  state.ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === 'NEW_ALERT') {
      showToast(`🔔 New Prioritized Alert: ${msg.data.title}`);
      loadAllData();
    } else if (msg.type === 'INCIDENT_UPDATE') {
      showToast(`🚨 Incident Updated: ${msg.data.incident_id}`);
      loadAllData();
    } else if (msg.type === 'PLAYBOOK_ACTION') {
      showToast(`⚡ Playbook Activity: ${msg.data.action}`);
      if (state.currentView === 'playbooks') loadPlaybookExecution();
    }
  };

  state.ws.onclose = () => {
    document.getElementById('conn-text').textContent = 'RECONNECTING...';
    setTimeout(initWebSocket, 4000);
  };
}

// --- Data Fetching ---
function loadAllData() {
  loadAlerts();
  loadIncidents();
  if (state.currentView === 'audit') renderAudit();
  if (state.currentView === 'platform') renderPlatform();
}

function loadAlerts() {
  fetch(`/api/alerts?tenant=${state.currentTenant}`)
    .then(r => r.json())
    .then(data => {
      state.alerts = data;
      document.getElementById('stat-active-alerts').textContent = data.length;
      document.getElementById('badge-alerts-count').textContent = data.length;
      document.getElementById('alert-queue-counter').textContent = `${data.length} Alerts`;
      
      const p1Count = data.filter(a => a.risk?.priority === 'P1 Critical').length;
      document.getElementById('stat-p1-count').textContent = p1Count;
      renderAlerts();
    });
}

function loadIncidents() {
  fetch(`/api/incidents?tenant=${state.currentTenant}`)
    .then(r => r.json())
    .then(data => {
      state.incidents = data;
      document.getElementById('badge-incidents-count').textContent = data.length;
      if (!state.selectedIncident && data.length > 0) {
        state.selectedIncident = data[0];
      }
      renderIncidents();
      if (state.currentView === 'investigation') renderInvestigation();
      if (state.currentView === 'commander') renderCommander();
    });
}

// --- Render View 1: SOC Operations ---
function renderAlerts() {
  const tbody = document.getElementById('tbody-alerts');
  if (!tbody) return;

  if (state.alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 2rem;">No alerts currently in queue. Click "⚡ Ingestion Simulator" to inject test telemetry.</td></tr>`;
    return;
  }

  tbody.innerHTML = state.alerts.map(alert => {
    const sevClass = alert.risk?.priority === 'P1 Critical' ? 'badge-critical' : 
                     (alert.risk?.priority === 'P2 High' ? 'badge-high' : 
                     (alert.risk?.priority === 'P3 Medium' ? 'badge-medium' : 'badge-low'));
    
    return `
      <tr>
        <td><span class="badge ${sevClass}">${alert.risk?.priority || 'Medium'}</span></td>
        <td>
          <div style="font-weight: 600; color: var(--text-primary);">${escapeHtml(alert.title)}</div>
          <div style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono);">${alert.alert_id} | ${new Date(alert.occurred_at).toLocaleTimeString()}</div>
        </td>
        <td>
          <div>${escapeHtml(alert.source?.vendor || 'Unknown')}</div>
          <div style="font-size: 0.72rem; color: var(--text-muted);">${alert.source?.source_type || 'connector'}</div>
        </td>
        <td>
          <span class="badge badge-neutral">${alert.entities?.primaryEntity || 'Unknown'}</span>
        </td>
        <td>
          <span style="color: ${alert.enrichment?.assetCriticality?.includes('Critical') ? 'var(--sev-critical)' : 'var(--text-secondary)'}; font-weight: 500;">
            ${alert.enrichment?.assetCriticality || 'Normal'}
          </span>
        </td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="showExplainableScore('${alert.alert_id}')" title="Click to view scoring formula breakdown">
            🎯 ${alert.risk?.score || 50}/100 ℹ️
          </button>
        </td>
        <td>
          <span class="badge ${alert.status === 'escalated' ? 'badge-critical' : (alert.status === 'suppressed' ? 'badge-neutral' : 'badge-warning')}">
            ${alert.status.toUpperCase()}
          </span>
        </td>
        <td>
          <button class="btn btn-primary btn-sm" onclick="openTriageModal('${alert.alert_id}')">Triage</button>
        </td>
      </tr>
    `;
  }).join('');
}

window.showExplainableScore = function(alertId) {
  const alert = state.alerts.find(a => a.alert_id === alertId);
  if (!alert) return;

  let factorsHtml = (alert.risk?.factors || []).map(f => `
    <div style="display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid var(--border-subtle);">
      <div>
        <strong>${f.factor}</strong>
        <div style="font-size: 0.75rem; color: var(--text-muted);">${f.reason}</div>
      </div>
      <span class="badge badge-critical">${f.weight}</span>
    </div>
  `).join('');

  alertModal(`🎯 Explainable Risk Score Breakdown (${alert.risk.priority})`, `
    <div style="margin-bottom: 1rem;">
      <div style="font-size: 1.8rem; font-weight: 700; color: var(--text-primary); font-family: var(--font-mono);">
        ${alert.risk.score} / 100
      </div>
      <p style="color: var(--text-secondary); font-size: 0.85rem;">
        Formula: <code>Priority = f(Severity, Confidence, Asset Criticality, Privilege, Impact, Threat Intel)</code>
      </p>
    </div>
    <div style="background: var(--bg-surface-elevated); padding: 1rem; border-radius: var(--radius-sm);">
      <h4 style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.5rem;">Contributing Risk Factors</h4>
      ${factorsHtml || '<p style="color: var(--text-muted);">Baseline standard ingestion score.</p>'}
    </div>
    <div style="margin-top: 1rem; font-size: 0.8rem; color: var(--text-muted);">
      Recommended Routing: <em>${alert.risk.defaultAction}</em>
    </div>
  `);
};

window.openTriageModal = function(alertId) {
  const alert = state.alerts.find(a => a.alert_id === alertId);
  if (!alert) return;
  state.selectedAlertForTriage = alert;

  document.getElementById('modal-triage-title').textContent = `Triage Alert: ${alert.title}`;
  document.getElementById('modal-triage-body').innerHTML = `
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
      <div class="stat-card">
        <span class="stat-title">Source Context</span>
        <div style="margin-top: 0.4rem; font-size: 0.85rem;"><strong>Vendor:</strong> ${alert.source?.vendor}</div>
        <div style="font-size: 0.85rem;"><strong>Host:</strong> ${alert.entities?.hosts?.join(', ') || 'N/A'}</div>
        <div style="font-size: 0.85rem;"><strong>User:</strong> ${alert.entities?.users?.join(', ') || 'N/A'}</div>
      </div>
      <div class="stat-card">
        <span class="stat-title">Enrichment Context</span>
        <div style="margin-top: 0.4rem; font-size: 0.85rem;"><strong>Criticality:</strong> ${alert.enrichment?.assetCriticality}</div>
        <div style="font-size: 0.85rem;"><strong>Service:</strong> ${alert.enrichment?.businessService}</div>
        <div style="font-size: 0.85rem;"><strong>Privilege:</strong> ${alert.enrichment?.identityPrivilege}</div>
      </div>
    </div>
    <div class="cyber-card" style="margin-bottom: 0;">
      <div class="card-header"><span class="card-title">Detection Findings</span></div>
      <div class="card-body">
        ${(alert.detections || []).map(d => `
          <div style="padding: 0.4rem 0; border-bottom: 1px solid var(--border-subtle);">
            <span class="badge badge-high">${d.method}</span> <strong>${d.title || d.indicator || 'Anomaly'}</strong>
            <div style="font-size: 0.75rem; color: var(--text-muted);">${d.stage || 'Execution'} | Confidence: ${(d.confidence*100).toFixed(0)}%</div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
  openModal('modal-triage');
};

function triageAlert(alertId, action, disposition) {
  fetch(`/api/alerts/${alertId}/triage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ disposition, action, user: state.currentRole })
  })
  .then(r => r.json())
  .then(() => {
    closeModals();
    showToast(`Alert triaged as ${disposition} (${action.toUpperCase()})`);
    loadAllData();
  });
}

// --- Render View 2: Incidents & Case Management ---
function renderIncidents() {
  const tbody = document.getElementById('tbody-incidents');
  if (!tbody) return;

  if (state.incidents.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 2rem;">No active incidents. Triage an alert to escalate into an incident case.</td></tr>`;
    return;
  }

  tbody.innerHTML = state.incidents.map(inc => {
    const sevClass = inc.severity.includes('P1') ? 'badge-critical' : (inc.severity.includes('P2') ? 'badge-high' : 'badge-medium');
    return `
      <tr>
        <td><strong style="color: var(--accent-cyan); font-family: var(--font-mono);">${inc.incident_id}</strong></td>
        <td>
          <div style="font-weight: 600; color: var(--text-primary);">${escapeHtml(inc.title)}</div>
          <div style="font-size: 0.72rem; color: var(--text-muted);">${inc.category} | ${inc.business_impact}</div>
        </td>
        <td><span class="badge ${sevClass}">${inc.severity}</span></td>
        <td>
          <select class="cyber-select badge badge-neutral" onchange="updateIncidentStatus('${inc.incident_id}', this.value)" style="cursor: pointer;">
            <option value="New" ${inc.status === 'New' ? 'selected' : ''}>New</option>
            <option value="Investigating" ${inc.status === 'Investigating' ? 'selected' : ''}>Investigating</option>
            <option value="Contained" ${inc.status === 'Contained' ? 'selected' : ''}>Contained</option>
            <option value="Recovering" ${inc.status === 'Recovering' ? 'selected' : ''}>Recovering</option>
            <option value="Resolved" ${inc.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
            <option value="Closed" ${inc.status === 'Closed' ? 'selected' : ''}>Closed</option>
          </select>
        </td>
        <td>${inc.owner}</td>
        <td>
          <span class="badge badge-neutral">${inc.affected_scope?.hosts?.join(', ') || 'workstation'}</span>
          <span class="badge badge-neutral">${inc.affected_scope?.users?.join(', ') || 'user'}</span>
        </td>
        <td style="min-width: 180px;">
          <div id="sla-box-${inc.incident_id}" style="font-size: 0.75rem; font-family: var(--font-mono);">
            <span>Containment: <strong>Tracking...</strong></span>
            <div class="sla-progress-bar"><div class="sla-progress-fill on-track" style="width: 35%;"></div></div>
          </div>
        </td>
        <td>
          <div style="display: flex; gap: 0.3rem;">
            <button class="btn btn-secondary btn-sm" onclick="selectIncidentForWorkspace('${inc.incident_id}')">Investigate</button>
            <button class="btn btn-primary btn-sm" onclick="openPlaybookForIncident('${inc.incident_id}')">Playbook</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  refreshSLATimers();
}

window.updateIncidentStatus = function(incidentId, newStatus) {
  fetch(`/api/incidents/${incidentId}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: newStatus, role: state.currentRole, user: 'soc-user' })
  })
  .then(r => r.json())
  .then(() => {
    showToast(`Incident status updated to ${newStatus}`);
    loadIncidents();
  });
};

window.selectIncidentForWorkspace = function(incidentId) {
  state.selectedIncident = state.incidents.find(i => i.incident_id === incidentId);
  switchView('investigation');
};

window.openPlaybookForIncident = function(incidentId) {
  state.selectedIncident = state.incidents.find(i => i.incident_id === incidentId);
  switchView('playbooks');
};

function refreshSLATimers() {
  if (!state.incidents || state.incidents.length === 0) return;
  for (const inc of state.incidents) {
    fetch(`/api/sla/${inc.incident_id}`)
      .then(r => r.json())
      .then(sla => {
        const box = document.getElementById(`sla-box-${inc.incident_id}`);
        if (!box) return;
        const cont = sla.milestones?.containment_decision;
        if (!cont) return;

        let fillClass = 'on-track';
        if (cont.state === 'critical-warning' || cont.state === 'breached') fillClass = 'breached';
        else if (cont.state === 'warning') fillClass = 'warning';
        else if (cont.state === 'caution') fillClass = 'caution';

        const remainingMins = Math.max(0, Math.floor(cont.remainingSec / 60));
        const statusText = cont.completedAt ? '✅ Met' : `${remainingMins}m remaining`;

        box.innerHTML = `
          <div style="display: flex; justify-content: space-between;">
            <span>Containment:</span>
            <strong style="color: ${fillClass === 'breached' ? 'var(--sev-critical)' : 'var(--text-primary)'};">${statusText}</strong>
          </div>
          <div class="sla-progress-bar">
            <div class="sla-progress-fill ${fillClass}" style="width: ${Math.min(100, Math.round(cont.ratio * 100))}%;"></div>
          </div>
        `;
      }).catch(() => {});
  }
}

// --- Render View 3: Investigation Workspace ---
function renderInvestigation() {
  const inc = state.selectedIncident;
  if (!inc) {
    document.getElementById('investigation-timeline').innerHTML = `<p style="color: var(--text-muted);">Please select an incident from the "Incidents & Cases" tab.</p>`;
    return;
  }

  document.getElementById('investigation-selected-inc').textContent = `${inc.incident_id} - ${inc.severity}`;

  // Render Timeline
  const timelineEl = document.getElementById('investigation-timeline');
  timelineEl.innerHTML = (inc.timeline || []).map(item => `
    <div class="timeline-item">
      <div class="timeline-dot"></div>
      <div class="timeline-content">
        <div class="timeline-time">${new Date(item.time).toLocaleTimeString()} UTC</div>
        <div class="timeline-text">${escapeHtml(item.event)}</div>
      </div>
    </div>
  `).join('');

  // Render Evidence Locker
  const evidenceEl = document.getElementById('evidence-container');
  if (!inc.evidence || inc.evidence.length === 0) {
    evidenceEl.innerHTML = `<p style="color: var(--text-muted); font-size: 0.85rem;">No forensic artifacts attached yet.</p>`;
  } else {
    evidenceEl.innerHTML = inc.evidence.map(evi => `
      <div style="background: var(--bg-surface-elevated); padding: 0.75rem; border-radius: var(--radius-sm); margin-bottom: 0.5rem; border-left: 3px solid var(--accent-cyan);">
        <div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: var(--text-muted);">
          <span>${evi.type} | ${evi.source}</span>
          <span>${new Date(evi.timestamp).toLocaleTimeString()}</span>
        </div>
        <div style="font-size: 0.85rem; font-weight: 500; margin: 0.2rem 0;">${escapeHtml(evi.description)}</div>
        <div style="font-size: 0.7rem; font-family: var(--font-mono); color: var(--accent-cyan); word-break: break-all;">
          Hash: ${evi.hash}
        </div>
      </div>
    `).join('');
  }

  // Render Entity Pivot Graph
  const entityEl = document.getElementById('entity-pivot-container');
  entityEl.innerHTML = `
    <div style="display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem;">
      ${(inc.affected_scope?.hosts || []).map(h => `<button class="badge badge-critical" onclick="pivotEntity('Host', '${h}')">💻 ${h}</button>`).join('')}
      ${(inc.affected_scope?.users || []).map(u => `<button class="badge badge-high" onclick="pivotEntity('User', '${u}')">👤 ${u}</button>`).join('')}
      ${(inc.affected_scope?.ips || []).map(ip => `<button class="badge badge-medium" onclick="pivotEntity('IP', '${ip}')">🌐 ${ip}</button>`).join('')}
    </div>
    <div id="pivot-results-box" style="font-size: 0.8rem; color: var(--text-muted); background: var(--bg-surface-elevated); padding: 0.75rem; border-radius: var(--radius-sm);">
      Click any entity above to pivot across cross-source telemetry, historical incidents, and threat intelligence.
    </div>
  `;
}

window.pivotEntity = function(type, value) {
  const box = document.getElementById('pivot-results-box');
  box.innerHTML = `
    <div style="color: var(--text-primary); font-weight: 600; margin-bottom: 0.4rem;">
      🔍 Pivot Query Results for ${type}: <span style="color: var(--accent-cyan);">${value}</span>
    </div>
    <ul style="padding-left: 1.2rem; line-height: 1.6;">
      <li>Associated with <strong>1 active critical incident</strong> in past 24 hours.</li>
      <li>Authentication status: Multi-factor authenticated via Azure AD (No anomalous travel).</li>
      <li>Threat Intelligence: Known host identity registered under asset group <em>Tier-1 Core Banking Ledger</em>.</li>
      <li>Endpoint agent health: Active, EDR telemetry streaming at 12 events/sec.</li>
    </ul>
  `;
};

function addAnalystNote() {
  const input = document.getElementById('input-analyst-note');
  const note = input.value.trim();
  if (!note || !state.selectedIncident) return;

  fetch(`/api/incidents/${state.selectedIncident.incident_id}/timeline`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ note, user: state.currentRole })
  })
  .then(r => r.json())
  .then(data => {
    input.value = '';
    state.selectedIncident.timeline = data.timeline;
    renderInvestigation();
    showToast('Investigative finding added to chronological timeline');
  });
}

function attachForensicEvidence() {
  if (!state.selectedIncident) return;
  const desc = prompt('Enter evidence description (e.g. Memory dump, Wireshark PCAP extract, PowerShell script payload):', 'PowerShell obfuscated base64 payload extracted from memory');
  if (!desc) return;

  fetch(`/api/incidents/${state.selectedIncident.incident_id}/evidence`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      type: 'Memory Forensic Artifact',
      source: 'CrowdStrike Falcon Sensor',
      description: desc,
      content: desc + Date.now(),
      user: state.currentRole
    })
  })
  .then(r => r.json())
  .then(() => {
    showToast('Forensic evidence hashed and committed to tamper-evident locker');
    loadIncidents();
  });
}

// --- Render View 4: Playbook Orchestration ---
function renderPlaybooks() {
  fetch('/api/playbooks')
    .then(r => r.json())
    .then(playbooks => {
      const catalogEl = document.getElementById('playbook-catalog-list');
      catalogEl.innerHTML = playbooks.map(pb => `
        <div class="stat-card" style="margin-bottom: 0.75rem; cursor: pointer;" onclick="triggerPlaybook('${pb.id}')">
          <div style="font-weight: 600; color: var(--accent-cyan); font-size: 0.9rem;">${pb.name}</div>
          <div style="font-size: 0.75rem; color: var(--text-muted); margin: 0.3rem 0;">${pb.description}</div>
          <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 0.5rem;">
            <span class="badge badge-neutral">v${pb.version}</span>
            <span class="badge badge-primary">Run Playbook ▶</span>
          </div>
        </div>
      `).join('');
    });
}

window.triggerPlaybook = function(playbookId) {
  if (!state.selectedIncident) {
    alert('Please declare or select an incident from the Incidents tab first.');
    return;
  }

  fetch('/api/playbooks/trigger', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      playbookId,
      incidentId: state.selectedIncident.incident_id,
      user: state.currentRole
    })
  })
  .then(r => r.json())
  .then(data => {
    state.activePlaybookExecution = data.execution;
    renderPlaybookExecution();
    showToast(`Playbook [${data.execution.playbookName}] started!`);
  });
};

function renderPlaybookExecution() {
  const exec = state.activePlaybookExecution;
  if (!exec) return;

  document.getElementById('active-playbook-title').textContent = `⚡ ${exec.playbookName} (Incident: ${exec.incidentId})`;
  const statusBadge = document.getElementById('active-playbook-status');
  statusBadge.textContent = exec.status.toUpperCase();
  statusBadge.className = `badge ${exec.status === 'Succeeded' ? 'badge-success' : (exec.status === 'Waiting for Approval' ? 'badge-warning' : 'badge-primary')}`;

  const container = document.getElementById('playbook-execution-steps');
  container.innerHTML = exec.steps.map(step => {
    const isWaiting = step.status === 'waiting_approval';
    const isCompleted = step.status === 'completed';
    const isRolledBack = step.status === 'rolled_back';

    return `
      <div class="playbook-step ${isWaiting ? 'waiting' : (isCompleted ? 'completed' : '')}">
        <div style="flex: 1;">
          <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.3rem;">
            <span class="badge ${step.actionClass === 'A3' || step.actionClass === 'A4' ? 'badge-critical' : 'badge-neutral'}">
              Class ${step.actionClass}
            </span>
            <strong style="color: var(--text-primary); font-size: 0.9rem;">${step.name}</strong>
          </div>
          <div style="font-size: 0.75rem; color: var(--text-muted);">
            ${step.output || 'Step execution pending or awaiting authorization'}
          </div>
          ${step.approval ? `
            <div style="margin-top: 0.4rem; font-size: 0.72rem; color: #34d399; font-family: var(--font-mono);">
              ✅ Approved by ${step.approval.approverUser} (${step.approval.approverRole}) - "${step.approval.justification}"
            </div>
          ` : ''}
          ${step.verificationResult ? `
            <div style="margin-top: 0.4rem; font-size: 0.72rem; color: var(--accent-cyan); font-family: var(--font-mono);">
              🔍 Verification: ${step.verificationResult.state}
            </div>
          ` : ''}
          ${isRolledBack ? `
            <div style="margin-top: 0.4rem; font-size: 0.72rem; color: #f87171; font-family: var(--font-mono);">
              ↩️ Rolled Back: ${step.rollback?.result}
            </div>
          ` : ''}
        </div>
        <div>
          ${isWaiting ? `
            <button class="btn btn-primary btn-sm" onclick="openApprovalModal('${exec.executionId}', '${step.id}')">
              ⚠️ Authorize Step
            </button>
          ` : (isCompleted && step.rollbackSupported && !isRolledBack ? `
            <button class="btn btn-danger btn-sm" onclick="rollbackPlaybookStep('${exec.executionId}', '${step.id}')">
              ↩️ Rollback
            </button>
          ` : `
            <span class="badge ${isCompleted ? 'badge-success' : 'badge-neutral'}">${step.status.toUpperCase()}</span>
          `)}
        </div>
      </div>
    `;
  }).join('');
}

window.openApprovalModal = function(executionId, stepId) {
  const exec = state.activePlaybookExecution;
  const step = exec.steps.find(s => s.id === stepId);
  state.pendingApprovalStep = { executionId, stepId, step };

  document.getElementById('modal-approval-body').innerHTML = `
    <p style="color: var(--text-secondary); margin-bottom: 1rem;">
      This action is classified as <strong>Class ${step.actionClass} (${step.actionClass === 'A3' ? 'High Impact' : 'Potentially Disruptive Dual Control'})</strong>. 
      In accordance with Least-Privilege & Separation-of-Duties policy, it cannot be executed autonomously without human authorization.
    </p>
    <div class="stat-card" style="margin-bottom: 1rem;">
      <div><strong>Step:</strong> ${step.name}</div>
      <div><strong>Incident Target:</strong> ${exec.incidentId}</div>
      <div><strong>Required Approver:</strong> ${step.approvalRole || 'Incident Commander'}</div>
      <div><strong>Your Active Role:</strong> <span style="color: var(--accent-cyan); font-weight: 600;">${state.currentRole}</span></div>
    </div>
    <div>
      <label style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600;">Mandatory Justification / Reason:</label>
      <input type="text" id="input-approval-reason" class="control-group" style="width: 100%; padding: 0.5rem; margin-top: 0.3rem;" value="Confirmed malicious beaconing activity verified against threat intelligence">
    </div>
  `;
  openModal('modal-approval');
};

function confirmStepApproval() {
  if (!state.pendingApprovalStep) return;
  const { executionId, stepId } = state.pendingApprovalStep;
  const reason = document.getElementById('input-approval-reason')?.value || 'Authorized by SOC Leader';

  fetch('/api/playbooks/approve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      executionId,
      stepId,
      role: state.currentRole,
      user: 'soc-leader',
      justification: reason
    })
  })
  .then(r => {
    if (!r.ok) return r.json().then(e => { throw new Error(e.error); });
    return r.json();
  })
  .then(data => {
    closeModals();
    state.activePlaybookExecution = data.execution;
    renderPlaybookExecution();
    showToast('Action authorized and executed successfully with verification check!');
  })
  .catch(err => {
    alert(`Authorization Error: ${err.message}`);
  });
}

window.rollbackPlaybookStep = function(executionId, stepId) {
  const reason = prompt('Enter rollback justification (audited):', 'Target endpoint verified clean after memory decontamination');
  if (!reason) return;

  fetch('/api/playbooks/rollback', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      executionId,
      stepId,
      role: state.currentRole,
      user: 'commander',
      reason
    })
  })
  .then(r => r.json())
  .then(data => {
    state.activePlaybookExecution = data.execution;
    renderPlaybookExecution();
    showToast('Rollback operation executed. Containment rule lifted.');
  });
};

// --- Render View 5: Incident Commander ---
function renderCommander() {
  const inc = state.selectedIncident || state.incidents[0];
  const container = document.getElementById('commander-incident-view');
  if (!inc) {
    container.innerHTML = `<p style="color: var(--text-muted);">No active major incidents.</p>`;
    return;
  }

  container.innerHTML = `
    <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 1.5rem;">
      <div>
        <h3 style="color: var(--text-primary); margin-bottom: 0.5rem;">${inc.title}</h3>
        <p style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 1rem;">
          Business Impact: <strong style="color: var(--sev-critical);">${inc.business_impact}</strong> | Category: <strong>${inc.category}</strong>
        </p>

        <div style="background: var(--bg-surface-elevated); padding: 1rem; border-radius: var(--radius-sm); margin-bottom: 1rem;">
          <h4 style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.5rem;">Blast Radius & Affected Scope</h4>
          <div style="display: flex; gap: 0.5rem;">
            <span class="badge badge-critical">Hosts: ${(inc.affected_scope?.hosts || []).join(', ')}</span>
            <span class="badge badge-high">Identities: ${(inc.affected_scope?.users || []).join(', ')}</span>
            <span class="badge badge-medium">IPs: ${(inc.affected_scope?.ips || []).join(', ')}</span>
          </div>
        </div>

        <div style="background: var(--bg-surface-elevated); padding: 1rem; border-radius: var(--radius-sm);">
          <h4 style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.5rem;">Commander Decision Checklist</h4>
          <div style="display: flex; flex-direction: column; gap: 0.4rem; font-size: 0.85rem;">
            <label><input type="checkbox" checked disabled> Ingestion & Threat Detection Signature Confirmed</label>
            <label><input type="checkbox" checked disabled> Host Containment (EDR Network Isolation)</label>
            <label><input type="checkbox"> Legal & Regulatory Breach Assessment (24h Window)</label>
            <label><input type="checkbox"> Executive Stakeholder Briefing (Within 30m SLA)</label>
          </div>
        </div>
      </div>

      <div>
        <div class="stat-card" style="margin-bottom: 1rem;">
          <span class="stat-title">Command Actions</span>
          <div style="display: flex; flex-direction: column; gap: 0.5rem; margin-top: 0.75rem;">
            <button class="btn btn-danger btn-sm" onclick="updateIncidentStatus('${inc.incident_id}', 'Contained')">Declare Contained</button>
            <button class="btn btn-primary btn-sm" onclick="openPIRModal()">Generate Post-Incident Report</button>
          </div>
        </div>
      </div>
    </div>
  `;
}

// --- Render View 6: Executive Cyber-Risk ---
function renderExecutive() {
  const el = document.getElementById('executive-summary-content');
  el.innerHTML = `
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;">
      <div class="stat-card">
        <h4 style="color: var(--accent-cyan); margin-bottom: 0.5rem;">Core Banking & Operations Resilience</h4>
        <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 1rem;">
          All business-critical financial trading applications and databases operated with zero unplanned downtime during recent cyber detection events.
        </p>
        <div style="font-size: 0.8rem; color: var(--text-muted);">
          Key Risk Indicator: <strong>Low Residual Exposure</strong>
        </div>
      </div>

      <div class="stat-card">
        <h4 style="color: var(--accent-indigo); margin-bottom: 0.5rem;">Incident Velocity & Defense SLAs</h4>
        <ul style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.7; padding-left: 1rem;">
          <li>100% of P1 Critical Alerts triaged within 5-minute threshold.</li>
          <li>Automated EDR containment reduced Mean Time to Contain by 24%.</li>
          <li>Zero data leakage identified across multi-region tenant boundary.</li>
        </ul>
      </div>
    </div>
  `;
}

// --- Render View 7: Compliance & Audit ---
function renderAudit() {
  fetch('/api/audit')
    .then(r => r.json())
    .then(records => {
      const tbody = document.getElementById('tbody-audit');
      if (!tbody) return;

      tbody.innerHTML = records.map(rec => `
        <tr>
          <td><strong style="color: var(--accent-cyan); font-family: var(--font-mono);">${rec.audit_id}</strong></td>
          <td style="font-family: var(--font-mono); font-size: 0.75rem;">${new Date(rec.occurred_at).toLocaleTimeString()} UTC</td>
          <td>
            <div>${rec.actor?.subject_id}</div>
            <div style="font-size: 0.72rem; color: var(--text-muted);">${(rec.actor?.roles || []).join(', ')}</div>
          </td>
          <td><span class="badge badge-neutral">${rec.action}</span></td>
          <td style="font-size: 0.75rem; font-family: var(--font-mono);">${rec.resource?.type || 'platform'}: ${rec.resource?.id || 'root'}</td>
          <td>
            <div style="font-size: 0.7rem; font-family: var(--font-mono); color: var(--accent-cyan);">P: ${rec.integrity?.payload_hash?.substring(0, 20)}...</div>
            <div style="font-size: 0.7rem; font-family: var(--font-mono); color: var(--text-muted);">B: ${rec.integrity?.previous_record_hash?.substring(0, 20)}...</div>
          </td>
          <td>
            <span class="badge ${rec.result === 'success' ? 'badge-success' : 'badge-critical'}">${rec.result.toUpperCase()}</span>
          </td>
        </tr>
      `).join('');
    });
}

function verifyAuditChain() {
  fetch('/api/audit/verify')
    .then(r => r.json())
    .then(res => {
      const statusBox = document.getElementById('chain-verification-status');
      if (res.isValid) {
        statusBox.innerHTML = `
          <div class="badge badge-success" style="padding: 0.6rem 1rem; width: 100%; justify-content: flex-start; font-size: 0.85rem;">
            🛡️ CRYPTOGRAPHIC AUDIT CHAIN VERIFIED: All ${res.totalRecords} records verified intact with SHA-256 block hash-chaining. Zero tamper detected.
          </div>
        `;
      } else {
        statusBox.innerHTML = `
          <div class="badge badge-critical" style="padding: 0.6rem 1rem; width: 100%; justify-content: flex-start; font-size: 0.85rem;">
            ⚠️ AUDIT CHAIN INTEGRITY VIOLATION: Tampered records detected at index ${res.violations.map(v => v.index).join(', ')}!
          </div>
        `;
      }
    });
}

// --- Render View 8: Platform & Autoscaling ---
function renderPlatform() {
  // Fetch Multi-Region
  fetch('/api/multi-region')
    .then(r => r.json())
    .then(mr => {
      const el = document.getElementById('multi-region-container');
      el.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 0.75rem;">
          ${Object.values(mr.regions).map(reg => `
            <div class="stat-card" style="border-left: 4px solid ${reg.status === 'Healthy' ? '#34d399' : '#f87171'};">
              <div style="display: flex; justify-content: space-between;">
                <strong>${reg.name}</strong>
                <span class="badge ${reg.status === 'Healthy' ? 'badge-success' : 'badge-warning'}">${reg.status}</span>
              </div>
              <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.3rem;">
                Quorum: ${reg.brokerQuorum} | Latency: ${reg.latencyMs}ms | RPO Lag: ${reg.rpoLagSec}s
              </div>
              <div style="font-size: 0.75rem; color: var(--accent-cyan); font-family: var(--font-mono); margin-top: 0.2rem;">
                Active Tenants: ${reg.activeTenants.join(', ') || 'Warm Reserve'} | Fencing Epoch: ${reg.fencingEpoch}
              </div>
            </div>
          `).join('')}
        </div>
      `;
    });

  // Fetch KEDA Autoscaling & OpenCost
  fetch('/api/autoscaling')
    .then(r => r.json())
    .then(as => {
      const el = document.getElementById('autoscaling-container');
      el.innerHTML = `
        <div style="margin-bottom: 0.75rem;">
          <div style="display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 0.3rem;">
            <span>Budget Burn (${as.guardrailState} State):</span>
            <strong>$${as.budget.currentSpend} / $${as.budget.limit} (${as.budget.burnPercent}%)</strong>
          </div>
          <div class="sla-progress-bar"><div class="sla-progress-fill on-track" style="width: ${as.budget.burnPercent}%;"></div></div>
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.5rem;">
          ${as.kedaScalers.map(s => `
            <div style="background: var(--bg-surface-elevated); padding: 0.6rem 0.8rem; border-radius: var(--radius-sm); display: flex; justify-content: space-between; font-size: 0.8rem;">
              <div>
                <strong>${s.name}</strong>
                <div style="font-size: 0.7rem; color: var(--text-muted);">Topic: ${s.topic} | Lag: ${s.currentLag}</div>
              </div>
              <span class="badge badge-primary">${s.desiredReplicas} Pods (KEDA)</span>
            </div>
          `).join('')}
        </div>
        <div style="margin-top: 0.75rem; font-size: 0.75rem; color: var(--text-muted);">
          OpenCost Unit Economics: <strong>${as.unitEconomics.costPerMillionEvents}</strong> per 1M events | <strong>${as.unitEconomics.costPerConfirmedIncident}</strong> per incident
        </div>
      `;
    });

  // Fetch Kafka Topics
  fetch('/api/eventbus/topics')
    .then(r => r.json())
    .then(data => {
      const el = document.getElementById('kafka-topics-container');
      el.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 0.75rem;">
          ${Object.entries(data.topicStats).map(([name, meta]) => `
            <div style="background: var(--bg-surface-elevated); padding: 0.75rem; border-radius: var(--radius-sm); border-top: 2px solid var(--accent-cyan);">
              <div style="font-size: 0.8rem; font-family: var(--font-mono); color: var(--accent-cyan); font-weight: 600;">${name}</div>
              <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.2rem;">
                Messages: <strong>${meta.messageCount}</strong> | Partitions: ${meta.partitions} | Retention: ${meta.retentionDays}d
              </div>
            </div>
          `).join('')}
        </div>
      `;
    });
}

function triggerFailoverPromotion() {
  if (!confirm('Promote Region-B (Secondary-South) to active tenant owner? This will increment the fencing epoch and fence Region-A to prevent split-brain execution.')) return;

  fetch('/api/multi-region/failover', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tenantId: state.currentTenant, user: state.currentRole })
  })
  .then(r => r.json())
  .then(res => {
    showToast(`Region promoted! Ownership Epoch: ${res.epoch} (${res.fencingToken})`);
    renderPlatform();
  });
}

// --- PIR Modal & Export ---
function openPIRModal() {
  const inc = state.selectedIncident || state.incidents[0];
  if (!inc) {
    alert('No incident available for post-incident review.');
    return;
  }
  loadPIR('technical');
  openModal('modal-pir');
}

function loadPIR(audience) {
  const inc = state.selectedIncident || state.incidents[0];
  fetch(`/api/pir/${inc.incident_id}?audience=${audience}&role=${state.currentRole}`)
    .then(r => r.json())
    .then(report => {
      const body = document.getElementById('modal-pir-body');
      if (audience === 'executive') {
        body.innerHTML = `
          <h2 style="color: var(--text-primary); margin-bottom: 0.5rem;">${report.title}</h2>
          <div class="stat-card" style="margin-bottom: 1rem;">
            <h4 style="color: var(--accent-cyan);">Executive Summary</h4>
            <p style="margin-top: 0.3rem;">${report.executiveSummary.summary}</p>
            <p style="margin-top: 0.3rem; color: #34d399;"><strong>Impact:</strong> ${report.executiveSummary.overallImpact}</p>
          </div>
          <div class="stat-card">
            <h4>Corrective Action Items</h4>
            <ul style="margin-top: 0.5rem; padding-left: 1.2rem;">
              ${report.correctiveActions.map(a => `<li><strong>${a.id}:</strong> ${a.description} (Owner: ${a.owner}, Due: ${a.dueDate})</li>`).join('')}
            </ul>
          </div>
        `;
      } else {
        // Technical
        body.innerHTML = `
          <h2 style="color: var(--text-primary); margin-bottom: 0.5rem;">${report.title}</h2>
          <div style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono); margin-bottom: 1rem;">
            PIR Identifier: ${report.pirId} | Incident: ${report.incidentId} | Generated: ${report.generatedAt}
          </div>
          <div class="stat-card" style="margin-bottom: 1rem;">
            <h4 style="color: var(--accent-cyan);">1. Executive Summary & Impact</h4>
            <p style="margin-top: 0.4rem; font-size: 0.85rem;">${report.sections?.executiveSummary?.summary}</p>
            <div style="margin-top: 0.4rem; font-size: 0.85rem; color: #34d399;"><strong>Status:</strong> ${report.sections?.executiveSummary?.overallImpact}</div>
          </div>
          <div class="stat-card" style="margin-bottom: 1rem;">
            <h4 style="color: var(--sev-critical);">2. Root Cause Analysis</h4>
            <p style="margin-top: 0.4rem; font-size: 0.85rem;">${report.sections?.rootCause?.primaryCause}</p>
            <ul style="margin-top: 0.3rem; padding-left: 1.2rem; font-size: 0.8rem; color: var(--text-muted);">
              ${(report.sections?.rootCause?.contributingFactors || []).map(f => `<li>${f}</li>`).join('')}
            </ul>
          </div>
          <div class="stat-card">
            <h4 style="color: var(--accent-emerald);">3. Actionable Corrective Actions</h4>
            <div style="margin-top: 0.5rem; display: flex; flex-direction: column; gap: 0.5rem;">
              ${(report.sections?.correctiveActions || []).map(a => `
                <div style="background: var(--bg-surface-elevated); padding: 0.5rem 0.75rem; border-radius: var(--radius-sm); font-size: 0.8rem;">
                  <div><strong>${a.actionId}:</strong> ${a.description}</div>
                  <div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.2rem;">
                    Owner: <strong>${a.owner}</strong> | Due: ${a.dueDate} | Proof: ${a.validationRequirement}
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
        `;
      }
    });
}

// --- Ingestion Simulator ---
function triggerAttack(scenario) {
  fetch('/api/simulate/attack', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario })
  })
  .then(r => r.json())
  .then(res => {
    closeModals();
    showToast(`⚡ Injected attack scenario: ${scenario} (${res.eventId})`);
    loadAllData();
  });
}

function declareManualIncident() {
  const title = prompt('Enter Incident Title:', 'Suspicious Domain Controller NTDS.dit Access');
  if (!title) return;

  fetch('/api/incidents', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      title,
      severity: 'P1 Critical',
      category: 'Privilege Escalation',
      business_impact: 'Active Directory Identity Core',
      tenant_id: state.currentTenant,
      user: state.currentRole
    })
  })
  .then(r => r.json())
  .then(inc => {
    showToast(`Incident ${inc.incident_id} created manually!`);
    loadIncidents();
  });
}

// --- Helpers: Modals & Toasts ---
function openModal(id) {
  document.getElementById(id).classList.add('active');
}

function closeModals() {
  document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
}

function alertModal(title, html) {
  const modal = document.getElementById('modal-triage');
  document.getElementById('modal-triage-title').textContent = title;
  document.getElementById('modal-triage-body').innerHTML = html;
  document.getElementById('btn-triage-escalate').style.display = 'none';
  document.getElementById('btn-triage-suppress').style.display = 'none';
  openModal('modal-triage');
}

function showToast(message) {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.innerHTML = `<span>🛡️</span> <span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 4000);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
