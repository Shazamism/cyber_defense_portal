const auditLedger = require('./auditLedger');

const ROLES = {
  'SOC Analyst': {
    tier: 'Operate',
    description: 'Triage, investigation, evidence collection, and escalation',
    permissions: [
      'alert:read:tenant',
      'alert:triage:queue',
      'alert:escalate:tenant',
      'incident:read:tenant',
      'incident:update:assigned',
      'investigation:search:tenant',
      'evidence:read:tenant',
      'evidence:create:assigned',
      'playbook:execute:low-risk', // A0, A1
      'task:update:assigned',
      'report:read:technical'
    ]
  },
  'Senior SOC Analyst': {
    tier: 'Operate',
    description: 'Complex investigations, peer review, and severity overrides',
    permissions: [
      'alert:read:tenant',
      'alert:triage:queue',
      'alert:escalate:tenant',
      'alert:suppress:tenant',
      'incident:read:tenant',
      'incident:update:tenant',
      'incident:reassign:tenant',
      'incident:severity-override:tenant',
      'investigation:search:tenant',
      'evidence:read:tenant',
      'evidence:create:tenant',
      'playbook:execute:low-risk',
      'playbook:execute:contained', // A2
      'response-action:approve:contained',
      'task:create:tenant',
      'task:update:tenant',
      'report:read:technical'
    ]
  },
  'Incident Responder': {
    tier: 'Operate',
    description: 'Containment, eradication, and recovery coordination',
    permissions: [
      'alert:read:tenant',
      'incident:read:tenant',
      'incident:update:tenant',
      'evidence:read:tenant',
      'evidence:create:tenant',
      'playbook:execute:approved',
      'response-action:execute:approved',
      'response-action:verify:tenant',
      'task:create:tenant',
      'task:update:tenant',
      'report:read:technical'
    ]
  },
  'Incident Commander': {
    tier: 'Approve',
    description: 'Major-incident leadership and high-impact action authorizations',
    permissions: [
      'incident:read:tenant',
      'incident:update:tenant',
      'incident:declare-major:tenant',
      'incident:close:tenant',
      'playbook:execute:approved',
      'response-action:approve:high-impact', // A3
      'response-action:approve:disruptive',  // A4 (dual control)
      'task:assign:tenant',
      'report:read:executive',
      'report:read:technical',
      'report:approve:tenant'
    ]
  },
  'SOC Manager': {
    tier: 'Govern',
    description: 'Queue, SLA, quality, staffing, and performance management',
    permissions: [
      'alert:read:tenant',
      'incident:read:tenant',
      'incident:reassign:tenant',
      'incident:close-review:tenant',
      'dashboard:read:manager',
      'metrics:read:tenant',
      'sla:configure:tenant',
      'sla:pause:tenant',
      'report:read:executive',
      'report:read:technical'
    ]
  },
  'Threat Hunter': {
    tier: 'Contribute',
    description: 'Hypothesis-driven investigation across events and assets',
    permissions: [
      'alert:read:tenant',
      'incident:read:tenant',
      'investigation:search:tenant',
      'investigation:pivot:tenant',
      'threat-intel:read:tenant',
      'threat-intel:create:tenant',
      'evidence:read:tenant',
      'evidence:create:tenant'
    ]
  },
  'System or Asset Owner': {
    tier: 'Contribute',
    description: 'Remediation of owned assets and business context contribution',
    permissions: [
      'incident:read:scoped-asset',
      'task:read:assigned',
      'task:update:assigned',
      'asset:context:update'
    ]
  },
  'Compliance or Risk Officer': {
    tier: 'Govern',
    description: 'Governance, control mapping, and evidence review',
    permissions: [
      'audit:read:tenant',
      'audit:verify:tenant',
      'audit:export:tenant',
      'incident:read:tenant',
      'evidence:read:tenant',
      'report:read:compliance',
      'control-mapping:read:tenant'
    ]
  },
  'Executive Viewer': {
    tier: 'Read',
    description: 'Business-risk posture and major-incident visibility',
    permissions: [
      'dashboard:read:executive',
      'incident:read:executive-summary',
      'report:read:executive'
    ]
  },
  'Tenant Administrator': {
    tier: 'Administer',
    description: 'Tenant configuration, integrations, connectors, and policies',
    permissions: [
      'tenant:configure:tenant',
      'integration:configure:tenant',
      'connector:manage:tenant',
      'policy:update:tenant',
      'user:manage:tenant',
      'audit:read:tenant'
    ]
  },
  'Platform Administrator': {
    tier: 'Administer',
    description: 'Shared infrastructure, event bus health, and system operations',
    permissions: [
      'platform:health:read',
      'event-bus:manage:platform',
      'autoscaler:configure:platform',
      'multi-region:failover:platform',
      'integration:runtime:manage'
    ]
  },
  'Security Auditor': {
    tier: 'Govern',
    description: 'Independent, tamper-evident audit and configuration review',
    permissions: [
      'audit:read:organization',
      'audit:verify:organization',
      'audit:export:organization',
      'incident:read:organization',
      'evidence:read:metadata',
      'report:read:compliance'
    ]
  }
};

class RBACService {
  constructor() {
    this.roles = ROLES;
    this.breakGlassSessions = [];
  }

  getRoles() {
    return Object.keys(this.roles).map(name => ({
      name,
      tier: this.roles[name].tier,
      description: this.roles[name].description,
      permissions: this.roles[name].permissions
    }));
  }

  hasPermission(roleName, requiredPermission, userTenant, targetTenant) {
    // Tenant isolation: if accessing another tenant, denied unless break-glass or auditor
    if (userTenant && targetTenant && userTenant !== targetTenant) {
      if (roleName !== 'Security Auditor' && !this.isBreakGlassActive(roleName)) {
        return false;
      }
    }

    const role = this.roles[roleName];
    if (!role) return false;

    // Direct match or wildcard matching
    const [reqRes, reqAct, reqScope] = requiredPermission.split(':');
    return role.permissions.some(p => {
      const [rRes, rAct, rScope] = p.split(':');
      const resMatch = rRes === '*' || rRes === reqRes;
      const actMatch = rAct === '*' || rAct === reqAct;
      const scopeMatch = rScope === '*' || rScope === reqScope || rScope === 'tenant';
      return resMatch && actMatch && scopeMatch;
    });
  }

  activateBreakGlass(subjectId, reason, tenantId) {
    const session = {
      id: `bg_${Date.now()}`,
      subjectId,
      reason,
      tenantId,
      activatedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(), // 1 hour max
      active: true
    };
    this.breakGlassSessions.push(session);

    auditLedger.log({
      tenant_id: tenantId,
      actor: { type: 'human', subject_id: subjectId, roles: ['Break-Glass Administrator'] },
      action: 'break-glass.activate',
      classification: 'restricted-security',
      reason,
      result: 'success'
    });

    return session;
  }

  isBreakGlassActive(subjectId) {
    const now = new Date();
    return this.breakGlassSessions.some(
      s => s.subjectId === subjectId && s.active && new Date(s.expiresAt) > now
    );
  }
}

const rbacService = new RBACService();
module.exports = rbacService;
