const express = require('express');
const http = require('http');
const path = require('path');
const cors = require('cors');
const { WebSocketServer } = require('ws');

const routes = require('./api/routes');
const eventBus = require('./services/eventBus');
const detectionEngine = require('./services/detectionEngine');
const auditLedger = require('./services/auditLedger');
const slaManager = require('./services/slaManager');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static frontend files
app.use(express.static(path.join(__dirname, '..', 'public')));

// Mount API routes
app.use(routes);

const server = http.createServer(app);

// WebSocket real-time broadcast engine
const wss = new WebSocketServer({ server });

function broadcast(type, data) {
  const msg = JSON.stringify({ type, data, timestamp: new Date().toISOString() });
  for (const client of wss.clients) {
    if (client.readyState === 1) { // OPEN
      client.send(msg);
    }
  }
}

// Hook event bus updates to WebSocket broadcast
eventBus.subscribe('security.ingress.raw.v1', 'ws-broadcaster', (rec) => {
  broadcast('RAW_EVENT', rec);
});
eventBus.subscribe('security.alert.received.v1', 'ws-broadcaster', (rec) => {
  broadcast('NEW_ALERT', rec.payload);
});
eventBus.subscribe('security.incident.lifecycle.v1', 'ws-broadcaster', (rec) => {
  broadcast('INCIDENT_UPDATE', rec.payload);
});
eventBus.subscribe('security.response.action.v1', 'ws-broadcaster', (rec) => {
  broadcast('PLAYBOOK_ACTION', rec.payload);
});

// Seed initial realistic SOC telemetry per PRD MVP specifications
function seedInitialData() {
  console.log('Seeding initial Defence Cyber Portal telemetry & incidents...');

  // Seed initial audit root block
  auditLedger.log({
    tenant_id: 'tenant_acme',
    actor: { type: 'system', subject_id: 'bootstrap', roles: ['Platform Administrator'] },
    action: 'system.bootstrap',
    classification: 'internal',
    reason: 'Defence Cyber Portal initial runtime initialization',
    result: 'success'
  });

  // Seed Scenario 1: Critical EDR Ransomware Attack
  const edrEvent = {
    event_type: 'security.alert.edr',
    vendor: 'CrowdStrike Falcon',
    title: 'Suspicious Encoded PowerShell Execution & Shadow Copy Deletion',
    severity: 'Critical',
    host: 'workstation-104',
    user: 'user@example.org',
    entities: {
      host: ['workstation-104'],
      user: ['user@example.org']
    },
    command_line: 'powershell.exe -Enc SQBFAFgAIAAoAE4AZQB3AC... && vssadmin delete shadows /all /quiet',
    process_name: 'powershell.exe',
    ip: '198.51.100.22'
  };

  const rawEnv1 = {
    event_id: 'evt_01J9RANSOMWARE_INIT',
    event_type: 'security.alert.received',
    event_version: '1.0',
    tenant_id: 'tenant_acme',
    source: {
      source_id: 'edr-prod-01',
      source_type: 'edr',
      vendor: 'CrowdStrike Falcon',
      connector_version: '1.3.0'
    },
    occurred_at: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
    received_at: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
    trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
    idempotency_key: 'edr-prod-01:alert-883921',
    classification: 'security-event',
    priority_hint: 'critical',
    payload_format: 'vendor-json',
    payload_hash: 'sha256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    payload: edrEvent
  };

  eventBus.publish('security.ingress.raw.v1', 'tenant_acme:edr-prod-01', rawEnv1);

  // Seed Scenario 2: Phishing Alert
  const emailEvent = {
    event_type: 'security.alert.email',
    vendor: 'Proofpoint Email Security',
    title: 'Credential Harvester Phishing URL Intercepted',
    severity: 'High',
    host: 'mail-edge-01',
    user: 'admin@example.org',
    sender: 'security-alert@auth-secure-verify.com',
    subject: 'Action Required: Confirm Office 365 Authentication Token',
    entities: {
      user: ['admin@example.org']
    },
    ip: '203.0.113.88'
  };

  const rawEnv2 = {
    event_id: 'evt_01J9PHISHING_INIT',
    event_type: 'security.alert.received',
    event_version: '1.0',
    tenant_id: 'tenant_acme',
    source: {
      source_id: 'email-sec-01',
      source_type: 'email',
      vendor: 'Proofpoint',
      connector_version: '1.1.0'
    },
    occurred_at: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
    received_at: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
    trace_id: '7ca31f3577b34da6a3ce929d0e0e9812',
    idempotency_key: 'email-sec-01:msg-44819',
    classification: 'security-event',
    priority_hint: 'high',
    payload_format: 'vendor-json',
    payload_hash: 'sha256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    payload: emailEvent
  };

  eventBus.publish('security.ingress.raw.v1', 'tenant_acme:email-sec-01', rawEnv2);

  // Initialize SLA for created incidents
  setTimeout(() => {
    for (const inc of detectionEngine.incidents) {
      slaManager.initIncidentSLA(inc.incident_id, inc.severity, inc.created_at);
    }
  }, 100);
}

server.listen(PORT, () => {
  console.log(`=============================================================`);
  console.log(`🛡️  DEFENCE CYBER PORTAL is running on http://localhost:${PORT}`);
  console.log(`⚡ Ingestion Gateway API: http://localhost:${PORT}/v1/events`);
  console.log(`📊 Operations Portal UI:  http://localhost:${PORT}`);
  console.log(`=============================================================`);
  seedInitialData();
});
