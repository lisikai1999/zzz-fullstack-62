<template>
  <div class="sensitive-view">
    <h2 class="page-title">Sensitive Information Findings</h2>

    <div class="card-section" v-if="stats">
      <el-row :gutter="20">
        <el-col :span="6">
          <el-statistic title="Total Findings" :value="stats.total_findings" />
        </el-col>
        <el-col :span="6">
          <el-statistic title="Critical/High" :value="stats.critical_count + stats.high_count" />
        </el-col>
        <el-col :span="6">
          <el-statistic title="Medium" :value="stats.medium_count" />
        </el-col>
        <el-col :span="6">
          <el-statistic title="Rules Triggered" :value="Object.keys(stats.by_rule || {}).length" />
        </el-col>
      </el-row>
    </div>

    <div class="card-section">
      <el-table :data="findings" style="width: 100%" stripe>
        <el-table-column prop="severity" label="Severity" width="100">
          <template #default="{ row }">
            <el-tag :type="severityType(row.severity)" size="small">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="rule_name" label="Rule" width="180" />
        <el-table-column prop="matched_text" label="Match" width="200">
          <template #default="{ row }">
            <code>{{ row.matched_text }}</code>
          </template>
        </el-table-column>
        <el-table-column prop="direction" label="Direction" width="140" />
        <el-table-column prop="context" label="Context" show-overflow-tooltip />
        <el-table-column prop="session_id" label="Session" width="80" />
      </el-table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, computed } from 'vue'
import { usePacketStore } from '../stores/packets'
import { useSensitiveStore } from '../stores/sensitive'

const packetStore = usePacketStore()
const sensitiveStore = useSensitiveStore()

const findings = computed(() => sensitiveStore.findings)
const stats = computed(() => sensitiveStore.stats)

function severityType(severity: string): string {
  if (severity === 'critical') return 'danger'
  if (severity === 'high') return 'warning'
  if (severity === 'medium') return 'info'
  return 'info'
}

onMounted(async () => {
  if (packetStore.currentPcapId) {
    await sensitiveStore.fetchFindings(packetStore.currentPcapId)
  }
  await sensitiveStore.fetchStats()
})
</script>
