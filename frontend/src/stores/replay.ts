import { defineStore } from 'pinia'
import { ref } from 'vue'
import api from '../api'

export const useReplayStore = defineStore('replay', () => {
  const currentJob = ref<any>(null)
  const replayResults = ref<any[]>([])
  const wsConnection = ref<WebSocket | null>(null)

  async function startReplay(sessionId: number, targetIp: string, targetPort: number,
                             speedFactor = 1.0, fieldOverrides: any = null) {
    const res = await api.post('/replay', {
      session_id: sessionId,
      target_ip: targetIp,
      target_port: targetPort,
      speed_factor: speedFactor,
      field_overrides: fieldOverrides,
    })
    currentJob.value = res.data
    return res.data
  }

  async function getReplayStatus(jobId: number) {
    const res = await api.get(`/replay/${jobId}`)
    currentJob.value = res.data
    return res.data
  }

  async function stopReplay(jobId: number) {
    await api.post(`/replay/${jobId}/stop`)
  }

  function connectWebSocket(jobId: number, onMessage: (data: any) => void) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${protocol}//${window.location.host}/api/ws/replay/${jobId}`)
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data)
      if (data.type !== 'heartbeat') {
        replayResults.value.push(data)
        onMessage(data)
      }
    }
    ws.onclose = () => { wsConnection.value = null }
    wsConnection.value = ws
  }

  function disconnectWebSocket() {
    if (wsConnection.value) {
      wsConnection.value.close()
      wsConnection.value = null
    }
  }

  return { currentJob, replayResults, startReplay, getReplayStatus,
           stopReplay, connectWebSocket, disconnectWebSocket }
})
