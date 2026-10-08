const crypto = require('crypto');

class AuditLedger {
  constructor() {
    this.records = [];
    this.lastHash = '0000000000000000000000000000000000000000000000000000000000000000';
  }

  log({
    tenant_id = 'tenant_acme',
    enterprise_id = 'enterprise_root',
    actor = { type: 'human', subject_id: 'soc-analyst-1', roles: ['SOC Analyst'] },
    action,
    resource = {},
    classification = 'restricted-security',
    purpose = 'incident-response',
    result = 'success',
    reason = '',
    source = { ip: '10.0.4.12', user_agent: 'portal-web' },
    change = { before: null, after: null }
  }) {
    const audit_id = `aud_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const now = new Date().toISOString();

    // Prepare core content for payload hashing
    const contentToHash = JSON.stringify({
      audit_id,
      tenant_id,
      actor,
      action,
      resource,
      result,
      reason,
      change,
      timestamp: now
    });

    const payload_hash = 'sha256:' + crypto.createHash('sha256').update(contentToHash).digest('hex');

    // Create block hash linking to the previous block (blockchain/hash-chain style)
    const blockPayload = `${this.lastHash}|${payload_hash}|${now}`;
    const block_hash = 'sha256:' + crypto.createHash('sha256').update(blockPayload).digest('hex');

    const record = {
      audit_id,
      occurred_at: now,
      received_at: now,
      tenant_id,
      enterprise_id,
      actor,
      action,
      resource,
      classification,
      purpose,
      result,
      reason,
      source: {
        ...source,
        trace_id: source.trace_id || crypto.randomBytes(16).toString('hex')
      },
      change,
      integrity: {
        payload_hash,
        previous_record_hash: this.lastHash,
        block_hash
      }
    };

    this.records.push(record);
    this.lastHash = block_hash;
    return record;
  }

  getAll(filter = {}) {
    let result = [...this.records];
    if (filter.tenant_id) {
      result = result.filter(r => r.tenant_id === filter.tenant_id);
    }
    if (filter.action) {
      result = result.filter(r => r.action.toLowerCase().includes(filter.action.toLowerCase()));
    }
    if (filter.subject_id) {
      result = result.filter(r => r.actor && r.actor.subject_id === filter.subject_id);
    }
    if (filter.incident_id) {
      result = result.filter(r => r.resource && r.resource.incident_id === filter.incident_id);
    }
    return result.reverse(); // Newest first
  }

  // Cryptographic audit chain verification per Section 7.5
  verifyIntegrity() {
    let currentExpectedPrev = '0000000000000000000000000000000000000000000000000000000000000000';
    const violations = [];

    for (let i = 0; i < this.records.length; i++) {
      const rec = this.records[i];
      if (rec.integrity.previous_record_hash !== currentExpectedPrev) {
        violations.push({
          index: i,
          audit_id: rec.audit_id,
          expected_prev: currentExpectedPrev,
          actual_prev: rec.integrity.previous_record_hash,
          error: 'Hash chain link broken - record may have been altered or deleted'
        });
      }

      // Recompute payload hash
      const contentToHash = JSON.stringify({
        audit_id: rec.audit_id,
        tenant_id: rec.tenant_id,
        actor: rec.actor,
        action: rec.action,
        resource: rec.resource,
        result: rec.result,
        reason: rec.reason,
        change: rec.change,
        timestamp: rec.occurred_at
      });
      const recomputedPayloadHash = 'sha256:' + crypto.createHash('sha256').update(contentToHash).digest('hex');
      if (recomputedPayloadHash !== rec.integrity.payload_hash) {
        violations.push({
          index: i,
          audit_id: rec.audit_id,
          expected_payload_hash: rec.integrity.payload_hash,
          recomputed_payload_hash: recomputedPayloadHash,
          error: 'Payload hash mismatch - record contents modified'
        });
      }

      currentExpectedPrev = rec.integrity.block_hash;
    }

    return {
      isValid: violations.length === 0,
      totalRecords: this.records.length,
      violations,
      verifiedAt: new Date().toISOString()
    };
  }
}

const auditLedger = new AuditLedger();
module.exports = auditLedger;
