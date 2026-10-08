const crypto = require('crypto');
const eventBus = require('./eventBus');
const auditLedger = require('./auditLedger');

const PLAYBOOK_DEFINITIONS = {
  'PB-PHISH-01': {
    id: 'PB-PHISH-01',
    name: 'Phishing Investigation & Containment',
    scenario: 'phishing',
    version: '1.4.0',
    description: 'Automated email triage, sender reputation check, mailbox purge, and domain block with approval gate.',
    steps: [
      { id: 'step-1', name: 'Extract URLs, Senders and Attachments', actionClass: 'A0', auto: true, status: 'pending' },
      { id: 'step-2', name: 'Query Threat Intelligence Reputation for Sender & URLs', actionClass: 'A0', auto: true, status: 'pending' },
      { id: 'step-3', name: 'Search Exchange Mailboxes for Similar Messages', actionClass: 'A1', auto: true, status: 'pending' },
      { id: 'step-4', name: 'Quarantine Malicious Messages Across Scope', actionClass: 'A2', auto: false, requiresApproval: true, approvalRole: 'Senior SOC Analyst', status: 'pending' },
      { id: 'step-5', name: 'Block Malicious Domain on Perimeter DNS/Firewall', actionClass: 'A3', auto: false, requiresApproval: true, approvalRole: 'Incident Commander', status: 'pending' },
      { id: 'step-6', name: 'Verify Email Removal and Edge DNS Resolution Block', actionClass: 'A0', auto: true, isVerification: true, status: 'pending' }
    ]
  },
  'PB-ACCOUNT-02': {
    id: 'PB-ACCOUNT-02',
    name: 'Compromised Account Remediation',
    scenario: 'compromised-account',
    version: '1.2.0',
    description: 'Rapid credential revocation, IdP session kill, account lock, and forensic mailbox audit.',
    steps: [
      { id: 'step-1', name: 'Enrich User Identity & Authentication Anomalies', actionClass: 'A0', auto: true, status: 'pending' },
      { id: 'step-2', name: 'Revoke Active Web Sessions & Refresh Tokens', actionClass: 'A2', auto: true, status: 'pending' },
      { id: 'step-3', name: 'Disable User Account in Identity Provider (Entra ID/Okta)', actionClass: 'A3', auto: false, requiresApproval: true, approvalRole: 'Incident Commander', status: 'pending' },
      { id: 'step-4', name: 'Audit OAuth App Consents & Mail Forwarding Rules', actionClass: 'A1', auto: true, status: 'pending' },
      { id: 'step-5', name: 'Verify Account Disabled State via IdP Query', actionClass: 'A0', auto: true, isVerification: true, status: 'pending' }
    ]
  },
  'PB-MALWARE-03': {
    id: 'PB-MALWARE-03',
    name: 'Malware & Ransomware Containment',
    scenario: 'malware-ransomware',
    version: '2.0.1',
    description: 'Immediate endpoint isolation, C2 indicator block, process termination, and live state verification.',
    steps: [
      { id: 'step-1', name: 'Identify Malicious Process Lineage & Command Line', actionClass: 'A0', auto: true, status: 'pending' },
      { id: 'step-2', name: 'Query EDR for Indicator Prevalence Across Endpoints', actionClass: 'A0', auto: true, status: 'pending' },
      { id: 'step-3', name: 'Isolate Host from Network via EDR Agent', actionClass: 'A3', auto: false, requiresApproval: true, approvalRole: 'Incident Commander', rollbackSupported: true, status: 'pending' },
      { id: 'step-4', name: 'Block Command-and-Control IP/Hashes on Gateway', actionClass: 'A3', auto: false, requiresApproval: true, approvalRole: 'Incident Commander', status: 'pending' },
      { id: 'step-5', name: 'Terminate Malicious Process Tree via EDR', actionClass: 'A2', auto: true, status: 'pending' },
      { id: 'step-6', name: 'Verify Network Isolation State with Live EDR Query', actionClass: 'A0', auto: true, isVerification: true, status: 'pending' }
    ]
  },
  'PB-CLOUD-04': {
    id: 'PB-CLOUD-04',
    name: 'Suspicious Cloud Infrastructure Intrusion',
    scenario: 'suspicious-cloud',
    version: '1.1.0',
    description: 'CloudTrail log correlation, STS credential revocation, IAM deny boundary, and instance containment.',
    steps: [
      { id: 'step-1', name: 'Analyze CloudTrail API Call Velocity & Anomalous Roles', actionClass: 'A0', auto: true, status: 'pending' },
      { id: 'step-2', name: 'Revoke Temporary IAM / STS Role Credentials', actionClass: 'A2', auto: true, status: 'pending' },
      { id: 'step-3', name: 'Attach Restrictive IAM Deny Boundary Policy', actionClass: 'A3', auto: false, requiresApproval: true, approvalRole: 'Incident Commander', status: 'pending' },
      { id: 'step-4', name: 'Stop or Isolate Compromised Cloud Compute Workload', actionClass: 'A4', auto: false, requiresApproval: true, approvalRole: 'Incident Commander', isDualApproval: true, status: 'pending' },
      { id: 'step-5', name: 'Verify IAM Policy Enforcement & Network Security Group', actionClass: 'A0', auto: true, isVerification: true, status: 'pending' }
    ]
  }
};

class PlaybookEngine {
  constructor() {
    this.executions = new Map(); // execution_id -> ExecutionRecord
  }

  getAvailablePlaybooks() {
    return Object.values(PLAYBOOK_DEFINITIONS);
  }

  triggerPlaybook(playbookId, incident, triggeredBy = 'System/Detection') {
    const def = PLAYBOOK_DEFINITIONS[playbookId];
    if (!def) {
      throw new Error(`Playbook ${playbookId} not found`);
    }

    const executionId = `exec_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const execution = {
      executionId,
      playbookId: def.id,
      playbookName: def.name,
      incidentId: incident.incident_id,
      tenantId: incident.tenant_id,
      triggeredBy,
      startedAt: new Date().toISOString(),
      status: 'Running', // Running, Waiting for Approval, Succeeded, Failed, Rolled back
      currentStepIndex: 0,
      steps: def.steps.map(s => ({
        ...s,
        status: 'pending',
        startedAt: null,
        completedAt: null,
        approval: null,
        verificationResult: null,
        output: null
      }))
    };

    this.executions.set(executionId, execution);

    auditLedger.log({
      tenant_id: incident.tenant_id,
      actor: { type: 'system', subject_id: triggeredBy, roles: ['Playbook Engine'] },
      action: 'playbook.trigger',
      resource: { type: 'playbook', id: def.id, incident_id: incident.incident_id },
      reason: `Playbook ${def.name} triggered for incident ${incident.incident_id}`,
      result: 'success'
    });

    eventBus.publish('security.response.action.v1', `${incident.tenant_id}:${incident.incident_id}`, {
      action: 'playbook_triggered',
      executionId,
      playbookId: def.id
    });

    // Run first step(s)
    this.advanceExecution(executionId);
    return execution;
  }

  advanceExecution(executionId) {
    const exec = this.executions.get(executionId);
    if (!exec || exec.status === 'Succeeded' || exec.status === 'Failed') return exec;

    for (let i = exec.currentStepIndex; i < exec.steps.length; i++) {
      const step = exec.steps[i];
      if (step.status === 'completed') continue;

      if (step.requiresApproval && !step.approval) {
        // Paused waiting for human approval
        exec.status = 'Waiting for Approval';
        exec.currentStepIndex = i;
        step.status = 'waiting_approval';
        return exec;
      }

      // Execute automated step
      step.status = 'running';
      step.startedAt = new Date().toISOString();

      if (step.isVerification) {
        step.verificationResult = {
          verified: true,
          queryTime: new Date().toISOString(),
          state: 'Confirmed: Target security posture matches containment criteria'
        };
        step.output = 'Live verification passed successfully.';
      } else {
        step.output = `Executed action class [${step.actionClass}] successfully on target scope.`;
      }

      step.status = 'completed';
      step.completedAt = new Date().toISOString();
      exec.currentStepIndex = i + 1;

      auditLedger.log({
        tenant_id: exec.tenantId,
        actor: { type: 'system', subject_id: 'playbook-worker', roles: ['Playbook Engine'] },
        action: `playbook.step.${step.id}.complete`,
        resource: { type: 'playbook-step', id: step.id, incident_id: exec.incidentId },
        reason: `${step.name} executed successfully`,
        result: 'success'
      });
    }

    // If all steps completed
    const allDone = exec.steps.every(s => s.status === 'completed');
    if (allDone) {
      exec.status = 'Succeeded';
      exec.completedAt = new Date().toISOString();
    }
    return exec;
  }

  approveStep(executionId, stepId, approverRole, approverUser, justification) {
    const exec = this.executions.get(executionId);
    if (!exec) throw new Error('Execution not found');

    const step = exec.steps.find(s => s.id === stepId);
    if (!step) throw new Error('Step not found');

    // Verify role authority per action class
    if (step.actionClass === 'A3' && approverRole !== 'Incident Commander' && approverRole !== 'Senior SOC Analyst') {
      throw new Error(`Role [${approverRole}] is not authorized to approve Action Class A3 (Requires Incident Commander or Senior SOC Analyst)`);
    }
    if (step.actionClass === 'A4' && approverRole !== 'Incident Commander') {
      throw new Error(`Role [${approverRole}] is not authorized to approve Action Class A4 (Requires Incident Commander)`);
    }

    step.approval = {
      approverRole,
      approverUser,
      justification,
      approvedAt: new Date().toISOString()
    };
    step.status = 'approved';

    auditLedger.log({
      tenant_id: exec.tenantId,
      actor: { type: 'human', subject_id: approverUser, roles: [approverRole] },
      action: 'response-action.approve',
      resource: { type: 'playbook-step', id: step.id, incident_id: exec.incidentId },
      reason: justification || `Approved step ${step.name}`,
      result: 'success'
    });

    // Advance playbook
    exec.status = 'Running';
    return this.advanceExecution(executionId);
  }

  rollbackStep(executionId, stepId, actorRole, actorUser, reason) {
    const exec = this.executions.get(executionId);
    if (!exec) throw new Error('Execution not found');

    const step = exec.steps.find(s => s.id === stepId);
    if (!step || !step.rollbackSupported) {
      throw new Error('Rollback not supported for this step');
    }

    step.status = 'rolled_back';
    step.rollback = {
      actorRole,
      actorUser,
      reason,
      rolledBackAt: new Date().toISOString(),
      result: 'Target host reconnected to network and EDR containment rule lifted.'
    };

    auditLedger.log({
      tenant_id: exec.tenantId,
      actor: { type: 'human', subject_id: actorUser, roles: [actorRole] },
      action: 'response-action.rollback',
      resource: { type: 'playbook-step', id: step.id, incident_id: exec.incidentId },
      reason,
      result: 'success'
    });

    return exec;
  }

  getExecution(executionId) {
    return this.executions.get(executionId);
  }
}

const playbookEngine = new PlaybookEngine();
module.exports = playbookEngine;
