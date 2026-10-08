const crypto = require('crypto');

class EventBus {
  constructor() {
    this.topics = {
      'security.ingress.raw.v1': { partitions: 12, retentionDays: 7, messages: [] },
      'security.alert.received.v1': { partitions: 12, retentionDays: 30, messages: [] },
      'security.alert.correlated.v1': { partitions: 12, retentionDays: 30, messages: [] },
      'security.context.enriched.v1': { partitions: 12, retentionDays: 30, messages: [] },
      'security.incident.lifecycle.v1': { partitions: 6, retentionDays: 365, messages: [] },
      'security.response.action.v1': { partitions: 6, retentionDays: 365, messages: [] },
      'security.audit.v1': { partitions: 6, retentionDays: 2555, messages: [] },
      'security.quarantine.v1': { partitions: 3, retentionDays: 30, messages: [] },
      'security.dlq.gateway.v1': { partitions: 3, retentionDays: 30, messages: [] }
    };

    this.subscribers = {};
    this.consumerOffsets = {};
    this.totalProduced = 0;
    this.totalConsumed = 0;
  }

  getPartition(key, totalPartitions) {
    if (!key) return 0;
    let hash = 0;
    for (let i = 0; i < key.length; i++) {
      hash = ((hash << 5) - hash) + key.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash) % totalPartitions;
  }

  publish(topicName, key, payload) {
    const topic = this.topics[topicName];
    if (!topic) {
      throw new Error(`Unknown topic: ${topicName}`);
    }

    const partition = this.getPartition(key, topic.partitions);
    const offset = topic.messages.length + 1;
    const record = {
      topic: topicName,
      partition,
      offset,
      key,
      payload,
      publishedAt: new Date().toISOString()
    };

    topic.messages.push(record);
    this.totalProduced++;

    // Asynchronously dispatch to subscribers for this topic
    if (this.subscribers[topicName]) {
      for (const subscriber of this.subscribers[topicName]) {
        setImmediate(() => {
          try {
            subscriber.handler(record);
            this.consumerOffsets[`${subscriber.group}:${topicName}`] = offset;
            this.totalConsumed++;
          } catch (err) {
            console.error(`Consumer [${subscriber.group}] error on [${topicName}]:`, err.message);
          }
        });
      }
    }

    return { topic: topicName, partition, offset, timestamp: record.publishedAt };
  }

  subscribe(topicName, group, handler) {
    if (!this.subscribers[topicName]) {
      this.subscribers[topicName] = [];
    }
    this.subscribers[topicName].push({ group, handler });
    if (!this.consumerOffsets[`${group}:${topicName}`]) {
      this.consumerOffsets[`${group}:${topicName}`] = 0;
    }
  }

  getMetrics() {
    const topicStats = {};
    for (const [name, meta] of Object.entries(this.topics)) {
      topicStats[name] = {
        messageCount: meta.messages.length,
        partitions: meta.partitions,
        retentionDays: meta.retentionDays,
        latestOffset: meta.messages.length
      };
    }

    const lagByGroup = {};
    for (const [subKey, offset] of Object.entries(this.consumerOffsets)) {
      const [group, topicName] = subKey.split(':');
      const topicMsgCount = this.topics[topicName]?.messages.length || 0;
      lagByGroup[subKey] = Math.max(0, topicMsgCount - offset);
    }

    return {
      totalProduced: this.totalProduced,
      totalConsumed: this.totalConsumed,
      topicStats,
      consumerLag: lagByGroup
    };
  }

  getLatest(topicName, limit = 20) {
    const topic = this.topics[topicName];
    if (!topic) return [];
    return topic.messages.slice(-limit).reverse();
  }
}

const eventBus = new EventBus();
module.exports = eventBus;
