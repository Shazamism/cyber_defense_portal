const crypto = require('crypto');
const eventBus = require('./eventBus');
const auditLedger = require('./auditLedger');

// Mock Threat Intelligence feeds & Assets CMDB & Identity Directory
const THREAT_INTEL_DB = {
  ips: {
    '198.51.100.22': { reputation: 'malicious', actor: 'APT-29 (Cozy Bear)', confidence: 0.95, category: 'C2 Server' },
    '203.0.113.88': { reputation: 'suspicious', actor: 'Unknown Scanner', confidence: 0.70, category: 'Brute Force' }
  },
  domains: {
    'auth-secure-verify.com': { reputation: 'malicious', campaign: 'Operation PhishShield', confidence: 0.98, category: 'Phishing Landing Page' },
    'data-exfil-drop.biz': { reputation: 'malicious', campaign: 'BlackCat/ALPHV', confidence: 0.92, category: 'Exfiltration Drop' }
  },
  hashes: {
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': { malware: 'Mimikatz', confidence: 0.99 },
    '8f4e2b1c3d5a7e9f0a2b4c6d8e0f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f': { malware: 'CobaltStrike Beacon', confidence: 0.95 }
  }
};

const ASSET_CMDB = {
  'workstation-104': { criticality: 'High', service: 'Financial Trading Operations', owner: 'SecOps', os: 'Windows 11 Enterprise' },
  'prod-db-01': { criticality: 'Tier-1 Critical', service: 'Core Banking Ledger', owner: 'Database Infra', os: 'RHEL 9.2' },
  'cloud-k8s-ingress': { criticality: 'High', service: 'Public Ingress Gateway', owner: 'Platform Eng', os: 'Container Linux' },
  'dev-sandbox-04': { criticality: 'Low', service: 'R&D Experimentation', owner: 'Dev Team', os: 'Ubuntu 22.04' }
};

const IDENTITY_DIRECTORY = {
  'user@example.org': { department: 'Finance & Treasury', privilege: 'Standard User', riskStatus: 'Normal', mfa: true },
  'admin@example.org': { department: 'Security Architecture', privilege: 'Domain Admin (Tier-0)', riskStatus: 'Elevated', mfa: true },
  'svc-payroll-sync': { department: 'Enterprise Systems', privilege: 'Service Account (Privileged)', riskStatus: 'Normal', mfa: false }
};

class DetectionEngine {
  constructor() {
    this.processedEventIds = new Set();
    this.alerts = [];
    this.incidents = [];
    this.thresholdCounters = new Map(); // Key -> count

    // Wire up to event bus raw ingress
    eventBus.subscribe('security.ingress.raw.v1', 'detection-engine', this.handleRawEvent.bind(this));
  }

  handleRawEvent(record) {
    const rawEnv = record.payload;
    if (!rawEnv || !rawEnv.event_id) return;

    // Stage 1: Intake & Deduplication check
    if (this.processedEventIds.has(rawEnv.event_id)) {
      return; // Already processed
    }
    this.processedEventIds.add(rawEnv.event_id);

    // Stage 2: Event-Time handling
    const occurredAt = new Date(rawEnv.occurred_at || Date.now());
    const receivedAt = new Date(rawEnv.received_at || Date.now());
    const latenessSec = Math.floor((receivedAt - occurredAt) / 1000);

    // Stage 3: Entity Extraction
    const entities = this.extractEntities(rawEnv.payload);

    // Stage 4: Detection Evaluation (Rules & TI Matching)
    const detections = this.evaluateDetections(rawEnv, entities);

    // Stage 5: Correlation & Deduplication
    const correlationKey = `${rawEnv.tenant_id}:${entities.primaryEntity || 'generic'}`;

    // Stage 6: Context Enrichment
    const enrichedContext = this.enrichContext(entities);

    // Stage 7: Explainable Risk Scoring
    const riskResult = this.calculateRiskScore(rawEnv, detections, enrichedContext);

    // Assemble Alert object
    const alertId = `alt_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const alertObj = {
      alert_id: alertId,
      event_id: rawEnv.event_id,
      tenant_id: rawEnv.tenant_id,
      source: rawEnv.source,
      occurred_at: rawEnv.occurred_at,
      received_at: rawEnv.received_at,
      lateness_sec: latenessSec,
      title: rawEnv.payload?.title || rawEnv.eventType || 'Security Detection Event',
      entities,
      detections,
      enrichment: enrichedContext,
      risk: riskResult,
      status: 'new', // new, triaged, suppressed, escalated
      disposition: null,
      raw_payload: rawEnv.payload,
      created_at: new Date().toISOString()
    };

    this.alerts.unshift(alertObj);

    // Publish to alert topic
    eventBus.publish('security.alert.received.v1', correlationKey, alertObj);

    // Alert-to-Incident Decisioning (Section 5 of Threat Detection spec)
    // If P1 Critical or P2 High, or High Confidence with Critical Asset, automatically suggest/create incident
    if (riskResult.priority === 'P1 Critical' || (riskResult.priority === 'P2 High' && enrichedContext.assetCriticality.includes('Critical'))) {
      this.autoPromoteToIncident(alertObj);
    }
  }

  extractEntities(payload = {}) {
    const text = JSON.stringify(payload);
    const entities = {
      users: [],
      hosts: [],
      ips: [],
      domains: [],
      hashes: [],
      primaryEntity: null
    };

    // IP regex
    const ipMatches = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
    entities.ips = [...new Set(ipMatches.filter(ip => ip !== '127.0.0.1'))];

    // Email / User regex
    const emailMatches = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
    entities.users = [...new Set(emailMatches)];

    // Known hosts / domains check
    if (payload.entities?.host) {
      entities.hosts = Array.isArray(payload.entities.host) ? payload.entities.host : [payload.entities.host];
    }
    if (payload.host || payload.hostname) {
      entities.hosts.push(payload.host || payload.hostname);
    }
    if (payload.user || payload.username) {
      entities.users.push(payload.user || payload.username);
    }

    // Default primary entity for correlation clustering
    entities.primaryEntity = entities.hosts[0] || entities.users[0] || entities.ips[0] || 'workstation-104';
    return entities;
  }

  evaluateDetections(rawEnv, entities) {
    const matched = [];
    const payloadStr = JSON.stringify(rawEnv.payload || {}).toLowerCase();

    // 1. Signature / Indicator matches against Threat Intel
    for (const ip of entities.ips) {
      if (THREAT_INTEL_DB.ips[ip]) {
        matched.push({
          method: 'Threat Intelligence Match',
          indicator: ip,
          type: 'IP',
          detail: THREAT_INTEL_DB.ips[ip],
          confidence: THREAT_INTEL_DB.ips[ip].confidence
        });
      }
    }
    for (const domain of (entities.domains || [])) {
      if (THREAT_INTEL_DB.domains[domain]) {
        matched.push({
          method: 'Threat Intelligence Match',
          indicator: domain,
          type: 'Domain',
          detail: THREAT_INTEL_DB.domains[domain],
          confidence: THREAT_INTEL_DB.domains[domain].confidence
        });
      }
    }

    // 2. Deterministic Behavioral Rules
    if (payloadStr.includes('powershell') && (payloadStr.includes('-enc') || payloadStr.includes('invoke-expression') || payloadStr.includes('downloadstring'))) {
      matched.push({
        method: 'Signature / Behavioral Rule',
        rule_id: 'DET-POWERSHELL-01',
        title: 'Obfuscated or Encoded PowerShell Process Execution',
        severity: 'High',
        confidence: 0.90,
        stage: 'Execution / Defense Evasion'
      });
    }

    if (payloadStr.includes('mimikatz') || payloadStr.includes('lsass') || payloadStr.includes('sekurlsa')) {
      matched.push({
        method: 'Signature Match',
        rule_id: 'DET-CRED-DUMP-02',
        title: 'Credential Access - LSASS Memory Injection Detected',
        severity: 'Critical',
        confidence: 0.98,
        stage: 'Credential Access'
      });
    }

    if (payloadStr.includes('failed login') || payloadStr.includes('4625') || payloadStr.includes('brute force')) {
      matched.push({
        method: 'Threshold Rule',
        rule_id: 'DET-AUTH-BRUTE-03',
        title: 'Authentication Threshold Exceeded (Multiple Failed Attempts)',
        severity: 'Medium',
        confidence: 0.85,
        stage: 'Credential Access'
      });
    }

    if (payloadStr.includes('ransom') || payloadStr.includes('.locked') || payloadStr.includes('vssadmin delete shadows')) {
      matched.push({
        method: 'Behavioral Rule',
        rule_id: 'DET-RANSOM-04',
        title: 'Inhibited System Recovery / Shadow Copy Deletion',
        severity: 'Critical',
        confidence: 0.99,
        stage: 'Impact'
      });
    }

    if (matched.length === 0) {
      matched.push({
        method: 'Standard Ingestion',
        rule_id: 'DET-GENERIC-INGEST',
        title: rawEnv.payload?.title || 'External Alert Ingestion',
        severity: rawEnv.priority_hint || 'Medium',
        confidence: 0.70,
        stage: 'Initial Access'
      });
    }

    return matched;
  }

  enrichContext(entities) {
    let assetCriticality = 'Medium';
    let assetOwner = 'Unassigned';
    let businessService = 'Enterprise IT';
    for (const h of entities.hosts) {
      if (ASSET_CMDB[h]) {
        assetCriticality = ASSET_CMDB[h].criticality;
        assetOwner = ASSET_CMDB[h].owner;
        businessService = ASSET_CMDB[h].service;
        break;
      }
    }

    let identityPrivilege = 'Standard User';
    let department = 'General Operations';
    for (const u of entities.users) {
      if (IDENTITY_DIRECTORY[u]) {
        identityPrivilege = IDENTITY_DIRECTORY[u].privilege;
        department = IDENTITY_DIRECTORY[u].department;
        break;
      }
    }

    return {
      assetCriticality,
      assetOwner,
      businessService,
      identityPrivilege,
      department,
      threatIntelMatchCount: entities.ips.filter(ip => THREAT_INTEL_DB.ips[ip]).length,
      vulnerabilities: ['CVE-2024-38077 (Remote Code Execution)', 'CVE-2023-36884 (Office RCE)']
    };
  }

  // Explainable Priority calculation per Section 3.2 Stage 7
  calculateRiskScore(rawEnv, detections, enrichment) {
    let score = 40; // baseline
    const factors = [];

    // Factor 1: Detection Severity
    const hasCriticalDet = detections.some(d => d.severity === 'Critical');
    const hasHighDet = detections.some(d => d.severity === 'High');
    if (hasCriticalDet) {
      score += 30;
      factors.push({ factor: 'Critical Detection Signature', weight: '+30', reason: 'High-confidence malicious tool or attack behavior identified' });
    } else if (hasHighDet) {
      score += 20;
      factors.push({ factor: 'High Detection Signature', weight: '+20', reason: 'Suspicious credential or execution anomaly' });
    }

    // Factor 2: Asset Criticality
    if (enrichment.assetCriticality.includes('Tier-1') || enrichment.assetCriticality.includes('Critical')) {
      score += 25;
      factors.push({ factor: 'Tier-1 Critical Asset', weight: '+25', reason: `Target host is part of ${enrichment.businessService}` });
    } else if (enrichment.assetCriticality === 'High') {
      score += 15;
      factors.push({ factor: 'High Criticality Asset', weight: '+15', reason: `Target host owned by ${enrichment.assetOwner}` });
    }

    // Factor 3: Identity Privilege
    if (enrichment.identityPrivilege.includes('Admin') || enrichment.identityPrivilege.includes('Privileged')) {
      score += 15;
      factors.push({ factor: 'Privileged Identity Risk', weight: '+15', reason: `Identity holds ${enrichment.identityPrivilege}` });
    }

    // Factor 4: Threat Intelligence
    if (enrichment.threatIntelMatchCount > 0) {
      score += 20;
      factors.push({ factor: 'Active Threat Intelligence Match', weight: '+20', reason: 'Entities cross-referenced with known threat campaigns' });
    }

    score = Math.min(100, Math.max(10, score));

    let priority = 'P4 Low';
    let defaultAction = 'Automated enrichment and low-priority queue';
    if (score >= 80) {
      priority = 'P1 Critical';
      defaultAction = 'Immediate escalation, major incident consideration, response playbook activation';
    } else if (score >= 60) {
      priority = 'P2 High';
      defaultAction = 'Immediate analyst assignment and short SLA containment';
    } else if (score >= 40) {
      priority = 'P3 Medium';
      defaultAction = 'Analyst triage queue for investigation';
    }

    return {
      score,
      priority,
      defaultAction,
      confidence: 0.92,
      factors
    };
  }

  autoPromoteToIncident(alert) {
    const incidentId = `inc_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const incident = {
      incident_id: incidentId,
      tenant_id: alert.tenant_id,
      title: `[${alert.risk.priority}] ${alert.title}`,
      category: alert.detections[0]?.stage || 'Malware / Intrusion',
      severity: alert.risk.priority,
      confidence: alert.risk.confidence,
      status: 'New', // New, Triage, Investigating, Contained, Recovering, Monitoring, Resolved, Closed
      owner: 'Unassigned',
      affected_scope: {
        hosts: alert.entities.hosts,
        users: alert.entities.users,
        ips: alert.entities.ips
      },
      business_impact: alert.enrichment.businessService,
      originating_alert_id: alert.alert_id,
      timeline: [
        { time: alert.occurred_at, event: 'Attack activity occurred on source system' },
        { time: alert.received_at, event: `Gateway accepted event and normalized canonical envelope (ID: ${alert.event_id})` },
        { time: new Date().toISOString(), event: `Threat Detection Engine evaluated priority as ${alert.risk.priority} (Score: ${alert.risk.score}/100)` },
        { time: new Date().toISOString(), event: `Incident ${incidentId} opened from alert ${alert.alert_id}` }
      ],
      evidence: [
        {
          id: `evi_${Date.now()}_1`,
          type: 'Raw Event Payload',
          source: alert.source.vendor,
          hash: alert.raw_payload ? crypto.createHash('sha256').update(JSON.stringify(alert.raw_payload)).digest('hex') : '',
          classification: 'Restricted-Security',
          timestamp: new Date().toISOString(),
          description: 'Initial raw source telemetry from connector'
        }
      ],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    this.incidents.unshift(incident);
    alert.incident_id = incidentId;
    alert.status = 'escalated';

    // Publish to incident lifecycle topic
    eventBus.publish('security.incident.lifecycle.v1', `${incident.tenant_id}:${incidentId}`, incident);

    auditLedger.log({
      tenant_id: alert.tenant_id,
      action: 'incident.create.automatic',
      resource: { type: 'incident', id: incidentId },
      reason: `Automated incident creation for ${alert.risk.priority} alert`,
      result: 'success'
    });

    return incident;
  }
}

const detectionEngine = new DetectionEngine();
module.exports = detectionEngine;
