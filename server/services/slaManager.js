const auditLedger = require('./auditLedger');

const SLA_TARGETS_MS = {
  'P1 Critical': {
    acknowledge: 5 * 60 * 1000,
    initial_triage: 15 * 60 * 1000,
    containment_decision: 30 * 60 * 1000,
    stakeholder_update: 30 * 60 * 1000,
    closure_review: 5 * 24 * 60 * 60 * 1000
  },
  'P2 High': {
    acknowledge: 15 * 60 * 1000,
    initial_triage: 60 * 60 * 1000,
    containment_decision: 4 * 60 * 60 * 1000,
    stakeholder_update: 4 * 60 * 60 * 1000,
    closure_review: 10 * 24 * 60 * 60 * 1000
  },
  'P3 Medium': {
    acknowledge: 4 * 60 * 60 * 1000,
    initial_triage: 8 * 60 * 60 * 1000,
    containment_decision: 24 * 60 * 60 * 1000,
    stakeholder_update: 24 * 60 * 60 * 1000,
    closure_review: 20 * 24 * 60 * 60 * 1000
  },
  'P4 Low': {
    acknowledge: 8 * 60 * 60 * 1000,
    initial_triage: 24 * 60 * 60 * 1000,
    containment_decision: 48 * 60 * 60 * 1000,
    stakeholder_update: 72 * 60 * 60 * 1000,
    closure_review: 30 * 24 * 60 * 60 * 1000
  }
};

class SLAManager {
  constructor() {
    this.incidentTimers = new Map();
  }

  initIncidentSLA(incidentId, priority, createdAt = new Date()) {
    const targets = SLA_TARGETS_MS[priority] || SLA_TARGETS_MS['P3 Medium'];
    const startTime = new Date(createdAt).getTime();

    const slaRecord = {
      incidentId,
      priority,
      createdAt: new Date(createdAt).toISOString(),
      isPaused: false,
      pauseReason: null,
      pausedAt: null,
      totalPausedMs: 0,
      milestones: {
        acknowledge: { targetMs: targets.acknowledge, completedAt: null, isBreached: false },
        initial_triage: { targetMs: targets.initial_triage, completedAt: null, isBreached: false },
        containment_decision: { targetMs: targets.containment_decision, completedAt: null, isBreached: false },
        stakeholder_update: { targetMs: targets.stakeholder_update, completedAt: null, isBreached: false },
        closure_review: { targetMs: targets.closure_review, completedAt: null, isBreached: false }
      }
    };

    this.incidentTimers.set(incidentId, slaRecord);
    return slaRecord;
  }

  completeMilestone(incidentId, milestoneName, completedBy = 'analyst') {
    const sla = this.incidentTimers.get(incidentId);
    if (!sla || !sla.milestones[milestoneName]) return null;

    const msObj = sla.milestones[milestoneName];
    if (!msObj.completedAt) {
      msObj.completedAt = new Date().toISOString();
      const elapsed = Date.now() - new Date(sla.createdAt).getTime() - sla.totalPausedMs;
      msObj.isBreached = elapsed > msObj.targetMs;

      auditLedger.log({
        tenant_id: 'tenant_acme',
        actor: { type: 'human', subject_id: completedBy, roles: ['SOC Analyst'] },
        action: `sla.milestone.${milestoneName}.complete`,
        resource: { type: 'incident', id: incidentId },
        reason: `Milestone ${milestoneName} completed in ${Math.round(elapsed/1000)}s (Target: ${Math.round(msObj.targetMs/1000)}s)`,
        result: msObj.isBreached ? 'breached' : 'success'
      });
    }
    return sla;
  }

  pauseTimer(incidentId, reason, actor = 'manager') {
    const sla = this.incidentTimers.get(incidentId);
    if (!sla || sla.isPaused) return sla;

    sla.isPaused = true;
    sla.pauseReason = reason;
    sla.pausedAt = Date.now();

    auditLedger.log({
      tenant_id: 'tenant_acme',
      actor: { type: 'human', subject_id: actor, roles: ['SOC Manager'] },
      action: 'sla.timer.pause',
      resource: { type: 'incident', id: incidentId },
      reason,
      result: 'success'
    });
    return sla;
  }

  resumeTimer(incidentId, actor = 'manager') {
    const sla = this.incidentTimers.get(incidentId);
    if (!sla || !sla.isPaused) return sla;

    const pausedDuration = Date.now() - sla.pausedAt;
    sla.totalPausedMs += pausedDuration;
    sla.isPaused = false;
    sla.pausedAt = null;
    sla.pauseReason = null;

    auditLedger.log({
      tenant_id: 'tenant_acme',
      actor: { type: 'human', subject_id: actor, roles: ['SOC Manager'] },
      action: 'sla.timer.resume',
      resource: { type: 'incident', id: incidentId },
      reason: `Timer resumed after ${Math.round(pausedDuration/1000)}s pause`,
      result: 'success'
    });
    return sla;
  }

  getSLAStatus(incidentId) {
    const sla = this.incidentTimers.get(incidentId);
    if (!sla) return null;

    const now = sla.isPaused ? sla.pausedAt : Date.now();
    const effectiveElapsed = now - new Date(sla.createdAt).getTime() - sla.totalPausedMs;

    const statusObj = {
      incidentId: sla.incidentId,
      priority: sla.priority,
      isPaused: sla.isPaused,
      pauseReason: sla.pauseReason,
      effectiveElapsedSec: Math.floor(effectiveElapsed / 1000),
      milestones: {}
    };

    for (const [name, data] of Object.entries(sla.milestones)) {
      const remainingMs = Math.max(0, data.targetMs - effectiveElapsed);
      const ratio = effectiveElapsed / data.targetMs;
      let state = 'on-track'; // normal
      if (data.completedAt) {
        state = data.isBreached ? 'completed-breached' : 'completed-met';
      } else if (effectiveElapsed > data.targetMs) {
        state = 'breached';
      } else if (ratio >= 0.9) {
        state = 'critical-warning'; // 90%
      } else if (ratio >= 0.75) {
        state = 'warning'; // 75%
      } else if (ratio >= 0.5) {
        state = 'caution'; // 50%
      }

      statusObj.milestones[name] = {
        targetSec: Math.floor(data.targetMs / 1000),
        remainingSec: Math.floor(remainingMs / 1000),
        completedAt: data.completedAt,
        state,
        ratio: Math.min(1.0, ratio)
      };
    }

    return statusObj;
  }
}

const slaManager = new SLAManager();
module.exports = slaManager;
