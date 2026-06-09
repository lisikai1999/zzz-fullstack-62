<template>
  <div class="tcp-timeline">
    <div class="timeline-header">
      <span class="side-label">Client</span>
      <span class="side-label right">Server</span>
    </div>
    <div class="timeline-body">
      <div
        v-for="entry in entries"
        :key="entry.packet_index"
        class="timeline-entry"
        :class="entry.direction"
      >
        <div class="entry-time">{{ formatDelta(entry.timestamp) }}</div>
        <div class="entry-arrow" :class="flagClass(entry.flags)">
          <span class="arrow-label">
            {{ entry.flags || '' }} {{ entry.payload_length > 0 ? `(${entry.payload_length}B)` : '' }}
          </span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
const props = defineProps<{ entries: any[] }>()

const baseTime = props.entries.length ? props.entries[0].timestamp : 0

function formatDelta(ts: number): string {
  const delta = (ts - baseTime) * 1000
  return `+${delta.toFixed(1)}ms`
}

function flagClass(flags: string | null): string {
  if (!flags) return ''
  if (flags.includes('SYN')) return 'flag-syn'
  if (flags.includes('FIN')) return 'flag-fin'
  if (flags.includes('RST')) return 'flag-rst'
  return 'flag-data'
}
</script>

<style scoped>
.tcp-timeline {
  max-height: 400px;
  overflow-y: auto;
}
.timeline-header {
  display: flex;
  justify-content: space-between;
  padding: 8px 60px;
  font-weight: 600;
  color: #606266;
  border-bottom: 1px solid #ebeef5;
}
.timeline-entry {
  display: flex;
  align-items: center;
  padding: 4px 0;
  gap: 8px;
}
.entry-time {
  width: 80px;
  font-size: 11px;
  color: #909399;
  text-align: right;
}
.entry-arrow {
  flex: 1;
  height: 24px;
  display: flex;
  align-items: center;
  position: relative;
  border-radius: 2px;
  padding: 0 8px;
  font-size: 11px;
}
.client_to_server .entry-arrow {
  background: linear-gradient(to right, #409eff22, transparent);
  border-left: 3px solid #409eff;
}
.server_to_client .entry-arrow {
  background: linear-gradient(to left, #67c23a22, transparent);
  border-right: 3px solid #67c23a;
  justify-content: flex-end;
}
.flag-syn { border-color: #67c23a !important; }
.flag-fin { border-color: #f56c6c !important; }
.flag-rst { border-color: #f56c6c !important; }
.arrow-label {
  color: #606266;
  font-family: monospace;
}
</style>
