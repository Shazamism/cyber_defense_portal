const assert = require('assert');
const http = require('http');

const BASE_URL = 'http://localhost:3000';

function makeRequest(path, method = 'GET', headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const reqHeaders = { 'Content-Type': 'application/json', ...headers };

    const req = http.request(url, { method, headers: reqHeaders }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch { parsed = data; }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed });
      });
    });

    req.on('error', reject);
    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

async function runTests() {
  console.log('🧪 Starting Defence Cyber Portal Automated Test Suite...');
  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    try {
      await fn();
      console.log(`  ✅ PASS: ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ FAIL: ${name}`);
      console.error(`     Error: ${err.message}`);
      failed++;
    }
  }

  // Test 1: Gateway Health
  await test('Gateway Health Check exposes 9 Kafka topics and connected status', async () => {
    const res = await makeRequest('/v1/health');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.status, 'healthy');
    assert.strictEqual(res.body.topics.length, 9);
    assert(res.body.topics.includes('security.ingress.raw.v1'));
  });

  // Test 2: Ingestion Authentication Guard
  await test('Gateway rejects unauthorized submission with 401', async () => {
    const res = await makeRequest('/v1/events', 'POST', {}, { test: true });
    assert.strictEqual(res.status, 401);
    assert.strictEqual(res.body.code, 'UNAUTHORIZED');
  });

  // Test 3: Ingestion Missing Headers Guard
  await test('Gateway rejects submission missing required headers with 400', async () => {
    const res = await makeRequest('/v1/events', 'POST', {
      'Authorization': 'Bearer test-token-123456789'
    }, { test: true });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(res.body.code, 'INVALID_HEADERS');
  });

  // Test 4: Valid Event Ingestion & Durable Acceptance (202 Accepted)
  const testIdempotencyKey = `idem-test-${Date.now()}`;
  const validPayload = {
    title: 'Automated Test Detection Event',
    host: 'workstation-104',
    user: 'user@example.org',
    severity: 'High'
  };

  let acceptedEventId = '';
  await test('Gateway accepts valid event with 202 Accepted and canonical envelope', async () => {
    const res = await makeRequest('/v1/events', 'POST', {
      'Authorization': 'Bearer test-token-123456789',
      'X-Tenant-ID': 'tenant_acme',
      'X-Source-ID': 'test-edr-source',
      'X-Idempotency-Key': testIdempotencyKey
    }, validPayload);

    assert.strictEqual(res.status, 202);
    assert.strictEqual(res.body.status, 'accepted');
    assert(res.body.event_id.startsWith('evt_'));
    assert.strictEqual(res.body.schema_version, '1.0');
    assert.strictEqual(res.body.topic, 'security.ingress.raw.v1');
    acceptedEventId = res.body.event_id;
  });

  // Test 5: Idempotency Duplicate Detection (200 OK)
  await test('Gateway detects duplicate submission and returns original event ID', async () => {
    const res = await makeRequest('/v1/events', 'POST', {
      'Authorization': 'Bearer test-token-123456789',
      'X-Tenant-ID': 'tenant_acme',
      'X-Source-ID': 'test-edr-source',
      'X-Idempotency-Key': testIdempotencyKey
    }, validPayload);

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.status, 'duplicate');
    assert.strictEqual(res.body.event_id, acceptedEventId);
  });

  // Test 6: Source Integrity Hash Violation Detection
  await test('Gateway rejects modified payload with same idempotency key as integrity violation', async () => {
    const tamperedPayload = { ...validPayload, title: 'Tampered Title' };
    const res = await makeRequest('/v1/events', 'POST', {
      'Authorization': 'Bearer test-token-123456789',
      'X-Tenant-ID': 'tenant_acme',
      'X-Source-ID': 'test-edr-source',
      'X-Idempotency-Key': testIdempotencyKey
    }, tamperedPayload);

    assert.strictEqual(res.status, 400);
    assert.strictEqual(res.body.code, 'SOURCE_INTEGRITY_VIOLATION');
  });

  // Test 7: Webhook Ingestion
  await test('Webhook ingestion accepts connector push events with 202 Accepted', async () => {
    const res = await makeRequest('/v1/webhooks/crowdstrike', 'POST', {
      'X-Tenant-ID': 'tenant_acme'
    }, { alert_name: 'C2 Beaconing Detected' });

    assert.strictEqual(res.status, 202);
    assert.strictEqual(res.body.status, 'accepted');
  });

  // Test 8: Cryptographic Audit Hash Chain Verification
  await test('Audit Ledger validates 100% cryptographic SHA-256 chain integrity with 0 violations', async () => {
    const res = await makeRequest('/api/audit/verify');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.isValid, true);
    assert.strictEqual(res.body.violations.length, 0);
    assert(res.body.totalRecords > 0);
  });

  // Test 9: Playbook Approval Gate & Execution
  await test('Playbook halts at High-Impact Step (A3) until authorized by Incident Commander', async () => {
    // 1. Get incidents
    const incRes = await makeRequest('/api/incidents');
    assert(incRes.body.length > 0);
    const targetInc = incRes.body[0];

    // 2. Trigger Malware Containment Playbook
    const triggerRes = await makeRequest('/api/playbooks/trigger', 'POST', {}, {
      playbookId: 'PB-MALWARE-03',
      incidentId: targetInc.incident_id,
      user: 'test-analyst'
    });
    assert.strictEqual(triggerRes.status, 200);
    const execution = triggerRes.body.execution;
    assert.strictEqual(execution.status, 'Waiting for Approval');

    // 3. Step 3 (Isolate Host - A3) must be waiting
    const step3 = execution.steps.find(s => s.id === 'step-3');
    assert.strictEqual(step3.status, 'waiting_approval');

    // 4. Authorize Step 3
    const approveRes = await makeRequest('/api/playbooks/approve', 'POST', {}, {
      executionId: execution.executionId,
      stepId: 'step-3',
      role: 'Incident Commander',
      user: 'commander-test',
      justification: 'Automated test containment authorized'
    });
    assert.strictEqual(approveRes.status, 200);
    const updatedStep3 = approveRes.body.execution.steps.find(s => s.id === 'step-3');
    assert.strictEqual(updatedStep3.status, 'completed');
  });

  // Test 10: Multi-Region Failover Promotion
  await test('Multi-Region promotion increments ownership epoch and fences former region', async () => {
    const res = await makeRequest('/api/multi-region/failover', 'POST', {}, {
      tenantId: 'tenant_acme',
      targetRegion: 'Region-B (Secondary-South)',
      user: 'Incident Commander'
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.newOwner, 'Region-B (Secondary-South)');
    assert(res.body.epoch > 100);
    assert(res.body.fencingToken.startsWith('fence-tok-epoch-'));
  });

  // Test 11: SLA Milestone Tracking
  await test('SLA manager tracks containment milestone countdown and supports pause/resume', async () => {
    const incRes = await makeRequest('/api/incidents');
    const targetInc = incRes.body[0];

    // Pause timer
    const pauseRes = await makeRequest(`/api/sla/${targetInc.incident_id}/pause`, 'POST', {}, {
      reason: 'Awaiting forensic vendor artifact upload',
      user: 'manager'
    });
    assert.strictEqual(pauseRes.status, 200);
    assert.strictEqual(pauseRes.body.isPaused, true);
    assert.strictEqual(pauseRes.body.pauseReason, 'Awaiting forensic vendor artifact upload');

    // Resume timer
    const resumeRes = await makeRequest(`/api/sla/${targetInc.incident_id}/resume`, 'POST', {}, {
      user: 'manager'
    });
    assert.strictEqual(resumeRes.status, 200);
    assert.strictEqual(resumeRes.body.isPaused, false);
  });

  console.log(`\n=================================================`);
  console.log(`📊 TEST RESULTS: ${passed} Passed, ${failed} Failed`);
  console.log(`=================================================`);

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
