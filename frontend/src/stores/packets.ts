import { defineStore } from 'pinia'
import { ref } from 'vue'
import api from '../api'

export const usePacketStore = defineStore('packets', () => {
  const currentPcapId = ref<number | null>(null)
  const pcapList = ref<any[]>([])
  const packets = ref<any[]>([])
  const totalPackets = ref(0)
  const currentPacket = ref<any>(null)
  const loading = ref(false)

  async function fetchPcapList() {
    const res = await api.get('/pcap')
    pcapList.value = res.data
  }

  async function uploadPcap(file: File) {
    const form = new FormData()
    form.append('file', file)
    const res = await api.post('/upload', form)
    currentPcapId.value = res.data.id
    return res.data
  }

  async function checkStatus(pcapId: number) {
    const res = await api.get(`/pcap/${pcapId}/status`)
    return res.data
  }

  async function fetchPackets(pcapId: number, page = 1, pageSize = 50) {
    loading.value = true
    try {
      const res = await api.get(`/pcap/${pcapId}/packets`, { params: { page, page_size: pageSize } })
      packets.value = res.data.packets
      totalPackets.value = res.data.total
    } finally {
      loading.value = false
    }
  }

  async function fetchPacketDetail(packetId: number) {
    const res = await api.get(`/packets/${packetId}`)
    currentPacket.value = res.data
    return res.data
  }

  return { currentPcapId, pcapList, packets, totalPackets, currentPacket, loading,
           fetchPcapList, uploadPcap, checkStatus, fetchPackets, fetchPacketDetail }
})
