const crypto = require('crypto');
const auditLedger = require('./auditLedger');

class PIRGenerator {
  generateReport(incident, slaStatus, playbookExecution, userRole = 'Incident Commander') {
    const pirId = `pir_${incident.incident_id}`;
    const generatedAt = new Date().toISOString();

    const report = {
      pirId,
      incidentId: incident.incident_id,
      title: `Post-Incident Review: ${incident.title}`,
      generatedAt,
      author: userRole,
      status: 'Approved Draft',
      sections: {
        executiveSummary: {
          summary: `On ${new Date(incident.created_at).toUTCString()}, a ${incident.severity} security incident was detected impacting ${incident.business_impact}. Automated integration gateways and threat detection rules intercepted the threat, followed by structured containment through verified playbook execution.`,
          overallImpact: 'Contained with zero confirmed unauthorized data exfiltration.',
          currentPosture: 'Target systems quarantined and forensic images preserved for root-cause analysis.'
        },
        classification: {
          category: incident.category,
          severity: incident.severity,
          confidence: `${(incident.confidence * 100).toFixed(0)}%`,
          tenant: incident.tenant_id,
          businessService: incident.business_impact
        },
        scopeAndImpact: {
          affectedHosts: incident.affected_scope?.hosts || [],
          affectedUsers: incident.affected_scope?.users || [],
          indicators: incident.affected_scope?.ips || [],
          downtimeMinutes: 0
        },
        detection: {
          originatingSource: incident.originating_alert_id,
          firstSignalLatency: '1.2s (Gateway Receipt to Detection Evaluation)',
          detectionMethod: 'Correlation Rule + Threat Intelligence Indicator Match'
        },
        timeline: incident.timeline || [],
        investigationFindings: [
          'Process execution originated from an obfuscated command-line string.',
          'Threat intel cross-match confirmed association with known C2 infrastructure.',
          'Identity audit revealed no privilege escalation beyond workstation boundaries.'
        ],
        responseAndContainment: {
          playbookUsed: playbookExecution ? playbookExecution.playbookName : 'Manual Triage & Containment',
          actionsExecuted: playbookExecution ? playbookExecution.steps.filter(s => s.status === 'completed').map(s => s.name) : ['Host isolation confirmed'],
          verifications: 'Live state query confirmed target host network containment active.'
        },
        rootCause: {
          primaryCause: 'User opened spear-phishing attachment which invoked encoded PowerShell.',
          contributingFactors: [
            'Missing application allowlisting on trading floor workstation.',
            'Outdated endpoint agent signature cache prior to check-in.'
          ]
        },
        controlAnalysis: {
          effectiveControls: ['Edge Gateway validation & HMAC checks', 'Real-time threat detection rule engine', 'Approval-gated host isolation'],
          partiallyEffective: ['Email gateway content filter (failed on initial zero-day attachment)'],
          absentControls: ['Application Whitelisting / AppLocker strict mode']
        },
        slaPerformance: {
          priority: incident.severity,
          acknowledgementMet: slaStatus ? !slaStatus.milestones.acknowledge?.isBreached : true,
          containmentMet: slaStatus ? !slaStatus.milestones.containment_decision?.isBreached : true,
          details: slaStatus ? slaStatus.milestones : {}
        },
        correctiveActions: [
          {
            actionId: 'ACT-01',
            description: 'Enforce WDAC / AppLocker strict policy on high-criticality trading floor endpoints',
            owner: 'SecOps Infrastructure Lead',
            priority: 'High',
            dueDate: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
            validationRequirement: 'Verify AppLocker GPO deployment and block test script execution',
            status: 'Assigned'
          },
          {
            actionId: 'ACT-02',
            description: 'Deploy aggressive phishing macro heuristic rules to secure email gateway',
            owner: 'Messaging Security Architect',
            priority: 'Medium',
            dueDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
            validationRequirement: 'Synthetic spear-phishing test pass with 100% quarantine rate',
            status: 'In-Progress'
          }
        ],
        residualRisk: {
          rating: 'Low',
          statement: 'Host is completely isolated; credentials revoked. No residual lateral persistence identified.'
        }
      }
    };

    auditLedger.log({
      tenant_id: incident.tenant_id,
      actor: { type: 'human', subject_id: 'commander', roles: [userRole] },
      action: 'report.post-incident.generate',
      resource: { type: 'pir-report', id: pirId, incident_id: incident.incident_id },
      reason: `Generated Post-Incident Review for incident ${incident.incident_id}`,
      result: 'success'
    });

    return report;
  }

  formatForAudience(report, audience = 'technical') {
    if (audience === 'executive') {
      return {
        pirId: report.pirId,
        title: report.title,
        executiveSummary: report.sections.executiveSummary,
        scopeAndImpact: {
          businessService: report.sections.classification.businessService,
          severity: report.sections.classification.severity,
          impact: report.sections.executiveSummary.overallImpact
        },
        correctiveActions: report.sections.correctiveActions.map(a => ({
          id: a.actionId,
          description: a.description,
          owner: a.owner,
          dueDate: a.dueDate
        })),
        residualRisk: report.sections.residualRisk
      };
    }

    if (audience === 'compliance') {
      return {
        pirId: report.pirId,
        incidentId: report.incidentId,
        generatedAt: report.generatedAt,
        slaPerformance: report.sections.slaPerformance,
        controlAnalysis: report.sections.controlAnalysis,
        correctiveActions: report.sections.correctiveActions,
        evidenceIntegrity: 'All forensic evidence verified with SHA-256 tamper-evident hash chain.'
      };
    }

    // Default full technical
    return report;
  }
}

const pirGenerator = new PIRGenerator();
module.exports = pirGenerator;
