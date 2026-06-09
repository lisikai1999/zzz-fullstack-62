import { defineStore } from 'pinia'
import { ref } from 'vue'
import api from '../api'

export const useSensitiveStore = defineStore('sensitive', () => {
  const findings = ref<any[]>([])
  const stats = ref<any>(null)

  async function fetchFindings(pcapId: number) {
    const res = await api.get(`/pcap/${pcapId}/sensitive`)
    findings.value = res.data
  }

  async function fetchStats() {
    const res = await api.get('/sensitive/stats')
    stats.value = res.data
    return res.data
  }

  return { findings, stats, fetchFindings, fetchStats }
})
