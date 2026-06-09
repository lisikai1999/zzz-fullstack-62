<template>
  <div class="replay-view">
    <h2 class="page-title">Traffic Replay</h2>

    <el-row :gutter="16">
      <el-col :span="8">
        <div class="card-section">
          <h3>Replay Configuration</h3>
          <ReplayPanel @start="onStartReplay" @stop="onStopReplay" :running="isRunning" />
        </div>
      </el-col>
      <el-col :span="16">
        <div class="card-section">
          <h3>Replay Results</h3>
          <el-table :data="replayResults" size="small" max-height="300" stripe>
            <el-table-column prop="packet_index" label="#" width="50" />
            <el-table-column prop="sent_bytes" label="Sent" width="70" />
            <el-table-column prop="response_bytes" label="Recv" width="70" />
            <el-table-column prop="timing_delta_ms" label="RTT(ms)" width="80" />
            <el-table-column prop="match" label="Match" width="70">
              <template #default="{ row }">
                <el-tag :type="row.match ? 'success' : 'danger'" size="small">
                  {{ row.match ? 'Yes' : 'No' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Similarity" width="100">
              <template #default="{ row }">
                {{ row.diff?.similarity_percent || 0 }}%
              </template>
            </el-table-column>
          </el-table>
        </div>

        <div class="card-section" v-if="selectedDiff">
          <h3>Response Diff</h3>
          <ResponseDiff :diff="selectedDiff" />
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useReplayStore } from '../stores/replay'
import ReplayPanel from '../components/replay/ReplayPanel.vue'
import ResponseDiff from '../components/replay/ResponseDiff.vue'

const replayStore = useReplayStore()
const replayResults = computed(() => replayStore.replayResults)
const isRunning = ref(false)
const selectedDiff = ref<any>(null)

async function onStartReplay(config: any) {
  replayStore.replayResults = []
  isRunning.value = true

  try {
    const job = await replayStore.startReplay(
      config.sessionId, config.targetIp, config.targetPort,
      config.speedFactor, config.fieldOverrides
    )
    replayStore.connectWebSocket(job.id, (data: any) => {
      if (!data.match) {
        selectedDiff.value = data.diff
      }
    })
  } catch (e) {
    isRunning.value = false
  }
}

function onStopReplay() {
  if (replayStore.currentJob?.id) {
    replayStore.stopReplay(replayStore.currentJob.id)
  }
  replayStore.disconnectWebSocket()
  isRunning.value = false
}
</script>
