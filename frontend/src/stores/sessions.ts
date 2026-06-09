import { defineStore } from 'pinia'
import { ref } from 'vue'
import api from '../api'

export const useSessionStore = defineStore('sessions', () => {
  const sessions = ref<any[]>([])
  const currentSession = ref<any>(null)
  const timeline = ref<any[]>([])
  const graph = ref<{ nodes: any[]; edges: any[] }>({ nodes: [], edges: [] })

  async function fetchSessions(pcapId: number) {
    const res = await api.get(`/pcap/${pcapId}/sessions`)
    sessions.value = res.data
  }

  async function fetchSessionDetail(sessionId: number) {
    const res = await api.get(`/sessions/${sessionId}`)
    currentSession.value = res.data
    return res.data
  }

  async function fetchTimeline(sessionId: number) {
    const res = await api.get(`/sessions/${sessionId}/timeline`)
    timeline.value = res.data
    return res.data
  }

  async function fetchGraph(pcapId: number) {
    const res = await api.get(`/pcap/${pcapId}/graph`)
    graph.value = res.data
    return res.data
  }

  return { sessions, currentSession, timeline, graph,
           fetchSessions, fetchSessionDetail, fetchTimeline, fetchGraph }
})
