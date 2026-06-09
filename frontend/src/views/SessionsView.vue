<template>
  <div class="sessions-view">
    <h2 class="page-title">Sessions & Communication Graph</h2>

    <el-row :gutter="16">
      <el-col :span="14">
        <div class="card-section" style="height: 500px">
          <h3>Communication Graph</h3>
          <SessionGraph :graph="graph" @select-session="onSelectSession" />
        </div>
      </el-col>
      <el-col :span="10">
        <div class="card-section" style="height: 500px; overflow-y: auto">
          <h3>Session List</h3>
          <el-table :data="sessions" highlight-current-row @current-change="onSelectSession" size="small">
            <el-table-column prop="src_ip" label="Source" width="120" />
            <el-table-column prop="dst_ip" label="Destination" width="120" />
            <el-table-column label="Ports" width="100">
              <template #default="{ row }">{{ row.src_port }}:{{ row.dst_port }}</template>
            </el-table-column>
            <el-table-column prop="app_protocol" label="Protocol" width="80" />
            <el-table-column prop="packet_count" label="Pkts" width="60" />
            <el-table-column prop="state" label="State" width="70">
              <template #default="{ row }">
                <el-tag :type="row.state === 'closed' ? 'success' : row.state === 'reset' ? 'danger' : 'info'" size="small">
                  {{ row.state }}
                </el-tag>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-col>
    </el-row>

    <div class="card-section" v-if="currentSession">
      <h3>Session Detail: {{ currentSession.src_ip }}:{{ currentSession.src_port }} → {{ currentSession.dst_ip }}:{{ currentSession.dst_port }}</h3>
      <el-descriptions :column="3" border size="small" style="margin-top: 12px">
        <el-descriptions-item label="Protocol">{{ currentSession.app_protocol || currentSession.protocol }}</el-descriptions-item>
        <el-descriptions-item label="Duration">{{ currentSession.duration_ms?.toFixed(1) }} ms</el-descriptions-item>
        <el-descriptions-item label="Total Bytes">{{ currentSession.total_bytes }}</el-descriptions-item>
        <el-descriptions-item label="State">{{ currentSession.state }}</el-descriptions-item>
      </el-descriptions>

      <div v-if="currentSession.app_decoded" style="margin-top: 12px">
        <h4>Application Layer</h4>
        <pre class="hex-dump">{{ JSON.stringify(currentSession.app_decoded, null, 2) }}</pre>
      </div>
    </div>

    <div class="card-section" v-if="timeline.length">
      <h3>TCP Flow Timeline</h3>
      <TcpTimeline :entries="timeline" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, computed } from 'vue'
import { usePacketStore } from '../stores/packets'
import { useSessionStore } from '../stores/sessions'
import SessionGraph from '../components/session/SessionGraph.vue'
import TcpTimeline from '../components/session/TcpTimeline.vue'

const packetStore = usePacketStore()
const sessionStore = useSessionStore()

const sessions = computed(() => sessionStore.sessions)
const currentSession = computed(() => sessionStore.currentSession)
const timeline = computed(() => sessionStore.timeline)
const graph = computed(() => sessionStore.graph)

async function onSelectSession(session: any) {
  if (!session?.id) return
  await sessionStore.fetchSessionDetail(session.id)
  await sessionStore.fetchTimeline(session.id)
}

onMounted(async () => {
  if (packetStore.currentPcapId) {
    await sessionStore.fetchSessions(packetStore.currentPcapId)
    await sessionStore.fetchGraph(packetStore.currentPcapId)
  }
})
</script>
