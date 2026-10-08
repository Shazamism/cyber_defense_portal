const auditLedger = require('./auditLedger');

class MultiRegionSimulator {
  constructor() {
    this.regions = {
      'Region-A (Primary-North)': {
        id: 'region-a',
        name: 'Region-A (Primary-North)',
        status: 'Healthy',
        brokerQuorum: '3/3 Brokers In-Sync',
        activeTenants: ['tenant_acme'],
        latencyMs: 12,
        rpoLagSec: 2,
        fencingEpoch: 104
      },
      'Region-B (Secondary-South)': {
        id: 'region-b',
        name: 'Region-B (Secondary-South)',
        status: 'Healthy',
        brokerQuorum: '3/3 Brokers In-Sync',
        activeTenants: ['tenant_globex'],
        latencyMs: 14,
        rpoLagSec: 3,
        fencingEpoch: 89
      }
    };

    this.tenantPlacements = {
      'tenant_acme': { primary: 'Region-A (Primary-North)', secondary: 'Region-B (Secondary-South)', currentOwner: 'Region-A (Primary-North)', epoch: 104 },
      'tenant_globex': { primary: 'Region-B (Secondary-South)', secondary: 'Region-A (Primary-North)', currentOwner: 'Region-B (Secondary-South)', epoch: 89 }
    };

    this.splitBrainDetected = false;
  }

  getStatus() {
    return {
      regions: this.regions,
      tenantPlacements: this.tenantPlacements,
      splitBrainDetected: this.splitBrainDetected,
      failoverReadiness: 'Ready (Target RPO < 15m, RTO < 60m met)'
    };
  }

  // Trigger regional failover promotion per Section 7.3
  triggerFailover(tenantId, targetRegionName, actor = 'Incident Commander') {
    const placement = this.tenantPlacements[tenantId];
    if (!placement) throw new Error(`Unknown tenant: ${tenantId}`);

    const prevOwner = placement.currentOwner;
    placement.epoch += 1;
    placement.currentOwner = targetRegionName;

    // Update region active tenant lists
    for (const reg of Object.values(this.regions)) {
      reg.activeTenants = reg.activeTenants.filter(t => t !== tenantId);
    }
    this.regions[targetRegionName].activeTenants.push(tenantId);
    this.regions[targetRegionName].fencingEpoch = placement.epoch;

    auditLedger.log({
      tenant_id: tenantId,
      actor: { type: 'human', subject_id: actor, roles: ['Platform Administrator'] },
      action: 'multi-region.failover.promoted',
      resource: { type: 'tenant-ownership', id: tenantId },
      reason: `Tenant promoted from ${prevOwner} to ${targetRegionName}. Ownership Epoch incremented to ${placement.epoch}. Stale region fenced.`,
      result: 'success'
    });

    return {
      success: true,
      tenantId,
      newOwner: targetRegionName,
      epoch: placement.epoch,
      fencingToken: `fence-tok-epoch-${placement.epoch}`
    };
  }

  simulateDegradation(regionName) {
    if (this.regions[regionName]) {
      this.regions[regionName].status = 'Degraded (Broker Lag Elevated)';
      this.regions[regionName].rpoLagSec = 45;
      this.regions[regionName].latencyMs = 85;
    }
    return this.regions[regionName];
  }

  simulateRestore(regionName) {
    if (this.regions[regionName]) {
      this.regions[regionName].status = 'Healthy';
      this.regions[regionName].rpoLagSec = 2;
      this.regions[regionName].latencyMs = 12;
    }
    return this.regions[regionName];
  }
}

const multiRegionSim = new MultiRegionSimulator();
module.exports = multiRegionSim;
