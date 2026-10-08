const eventBus = require('./eventBus');

class AutoscalingSimulator {
  constructor() {
    this.targetLagPerReplica = 500; // KEDA scale target
    this.guardrailState = 'Normal'; // Normal, Cost Watch, Cost Protection, Critical Budget Protection
    this.budgetLimit = 1500; // Monthly compute budget limit ($)
    this.currentMonthSpend = 642;

    this.nodePools = {
      'critical-pool': { type: 'On-Demand', nodes: 6, min: 3, max: 18, cpuAllocated: '74%', pods: 24 },
      'general-pool': { type: 'Mixed Spot/On-Demand', nodes: 4, min: 2, max: 12, cpuAllocated: '62%', pods: 16 },
      'batch-pool': { type: 'Preemptible/Spot', nodes: 2, min: 0, max: 8, cpuAllocated: '45%', pods: 6 }
    };
  }

  getScalingMetrics() {
    const busMetrics = eventBus.getMetrics();
    const rawTopicCount = busMetrics.topicStats['security.ingress.raw.v1']?.messageCount || 0;
    const alertTopicCount = busMetrics.topicStats['security.alert.received.v1']?.messageCount || 0;

    // Simulated consumer lag
    const rawLag = Math.max(0, rawTopicCount - busMetrics.totalConsumed);

    // KEDA Formula: ceil(lag / targetLagPerReplica)
    const desiredNormalizerReplicas = Math.min(12, Math.max(2, Math.ceil(rawLag / this.targetLagPerReplica) + 2));
    const desiredDetectionReplicas = Math.min(12, Math.max(2, Math.ceil(alertTopicCount / 20) + 2));

    // Calculate Unit Economics
    const totalEvents = Math.max(1, busMetrics.totalProduced);
    const costPerMillionEvents = 1.28; // OpenCost simulated estimate
    const costPerConfirmedIncident = 0.14;
    const costPerTenantDay = 4.80;

    return {
      guardrailState: this.guardrailState,
      budget: {
        limit: this.budgetLimit,
        currentSpend: this.currentMonthSpend,
        burnPercent: Math.round((this.currentMonthSpend / this.budgetLimit) * 100)
      },
      kedaScalers: [
        {
          name: 'raw-ingress-normalizer-scaler',
          topic: 'security.ingress.raw.v1',
          currentLag: rawLag,
          targetLag: this.targetLagPerReplica,
          minReplicas: 2,
          maxReplicas: 12,
          desiredReplicas: desiredNormalizerReplicas,
          currentReplicas: desiredNormalizerReplicas,
          stabilizationSec: 30
        },
        {
          name: 'threat-detection-rule-scaler',
          topic: 'security.alert.received.v1',
          currentLag: Math.floor(rawLag * 0.4),
          targetLag: 200,
          minReplicas: 2,
          maxReplicas: 12,
          desiredReplicas: desiredDetectionReplicas,
          currentReplicas: desiredDetectionReplicas,
          stabilizationSec: 30
        },
        {
          name: 'correlation-engine-scaler',
          topic: 'security.alert.correlated.v1',
          currentLag: 0,
          targetLag: 100,
          minReplicas: 2,
          maxReplicas: 8,
          desiredReplicas: 2,
          currentReplicas: 2,
          stabilizationSec: 60
        }
      ],
      nodePools: this.nodePools,
      unitEconomics: {
        costPerMillionEvents: `$${costPerMillionEvents.toFixed(2)}`,
        costPerConfirmedIncident: `$${costPerConfirmedIncident.toFixed(2)}`,
        costPerTenantDay: `$${costPerTenantDay.toFixed(2)}`,
        estimatedMonthlySavingsVsCommercial: '68% (Free KEDA + OpenCost + ClusterAutoscaler)'
      }
    };
  }

  setGuardrailState(state) {
    const valid = ['Normal', 'Cost Watch', 'Cost Protection', 'Critical Budget Protection'];
    if (valid.includes(state)) {
      this.guardrailState = state;
    }
    return this.guardrailState;
  }
}

const autoscalingSim = new AutoscalingSimulator();
module.exports = autoscalingSim;
